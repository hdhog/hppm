#include "hppm.h"

static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct sockaddr_storage connect_to_addr;
static int connect_to_addrlen;

#define MY_MAX_SEARCHED_PATTERNS (3*512)
#define MY_MAX_PATH 1024
#define MY_MAX_OUTPUT (1024*1024)

struct pattern
{
  std::string raw_pattern;
  pcre *re;
  pcre_extra *extra_re;
};
typedef pattern *ppattern;

struct filter_info
{
  std::vector < ppattern > *patterns;
};
typedef filter_info *pfilter_info;

struct callback_info
{
  bufferevent *client;
  bufferevent *server;
  unsigned long session_id;
  unsigned long packet_counter;
  static bool logging;
  static FILE *fd_out;
  static bool filtering;
  static pfilter_info pfi;
};
typedef callback_info *pcallback_info;

bool
  callback_info::logging = false;
FILE *
  callback_info::fd_out = NULL;
bool
  callback_info::filtering = false;
pfilter_info
  callback_info::pfi = NULL;

static char
  logfile[MY_MAX_PATH] = "";
static char
  regexp[MY_MAX_PATH] = "";

static void
readcb (struct bufferevent *bev, void *ctx);
static void
drained_writecb (struct bufferevent *bev, void *ctx);
static void
eventcb (struct bufferevent *bev, short what, void *ctx);

static inline bufferevent *
getpartner (struct bufferevent *bev, pcallback_info pcbi)
{
  if (pcbi->client == bev)
    return pcbi->server;
  if (pcbi->server == bev)
    return pcbi->client;
  return NULL;
}

static
  inline
  bool
is_clientside (struct bufferevent *bev, pcallback_info pcbi)
{
  return (pcbi->client == bev);
}

static
  inline
  bool
is_serverside (struct bufferevent *bev, pcallback_info pcbi)
{
  return (pcbi->server == bev);
}

void
logging_action (struct bufferevent *bev, pcallback_info pcbi,
		const char *data_out)
{
  std::string string_out;
  std::stringstream s;
  char
    ulong_str[12];

  string_out = "\nSession: ";
  s << pcbi->session_id;
  s >> string_out;
  string_out += "\nPacket: ";
  s << pcbi->packet_counter;
  s >> string_out;
  if (is_clientside (bev, pcbi))
    string_out += "\nPacket type: REQUEST";
  if (is_serverside (bev, pcbi))
    string_out += "\nPacket type: RESPONSE";

  string_out += "\nData: ";
  string_out += (char *) data_out;
  fwrite (string_out.c_str (), sizeof (char), string_out.length (),
	  pcbi->fd_out);
#ifdef _DEBUG
  printf ("%s\n", string_out.c_str ());
#endif
  fflush (pcbi->fd_out);
}

void
filtering_action (struct bufferevent *bev, pcallback_info pcbi,
		  char *data_out)
{
  unsigned int
    i = 0, j, start_offset;
  int
    pos[MY_MAX_SEARCHED_PATTERNS];
  for (; i < pcbi->pfi->patterns->size (); i++)
    {
      start_offset = 0;
      while (pcre_exec
	     ((*(pcbi->pfi->patterns))[i]->re,
	      (*(pcbi->pfi->patterns))[i]->extra_re, data_out,
	      strlen (data_out), start_offset, 0, pos,
	      MY_MAX_SEARCHED_PATTERNS) > 0)
	{
	  start_offset = pos[1];
#ifdef _DEBUG
	  printf ("\nRegexp %s matched at offset %d. Matched string %.*s",
		  (*(pcbi->pfi->patterns))[i]->raw_pattern.c_str (), pos[0],
		  pos[1] - pos[0], data_out + pos[0]);
#else
	  printf ("\n%.*s", pos[1] - pos[0], data_out + pos[0]);
#endif
	}
    }
}

static void
readcb (struct bufferevent *bev, void *ctx)
{
  pcallback_info
    pcbi = (pcallback_info) ctx;
  struct bufferevent *
    partner = getpartner (bev, pcbi);
  struct evbuffer *
  src, *
    dst;
  char *
    data_out = NULL;
  size_t
    len;

  src = bufferevent_get_input (bev);
  len = evbuffer_get_length (src);
  if (!partner)
    {
      evbuffer_drain (src, len);
      return;
    }

  data_out = (char *) calloc (len + 1, sizeof (char));
  evbuffer_copyout (src, data_out, len);

  if (pcbi->logging)
    {
      logging_action (bev, pcbi, data_out);
    }
  if (pcbi->filtering)
    {
      filtering_action (bev, pcbi, data_out);
    }
  free (data_out);
  dst = bufferevent_get_output (partner);
  pcbi->packet_counter++;
  evbuffer_add_buffer (dst, src);
  if (evbuffer_get_length (dst) >= MY_MAX_OUTPUT)
  {
   bufferevent_setcb (partner, readcb, drained_writecb, eventcb, bev);
   bufferevent_setwatermark (partner, EV_WRITE, MY_MAX_OUTPUT / 2, MY_MAX_OUTPUT);
   bufferevent_disable (bev, EV_READ);
  }
}

static void
drained_writecb (struct bufferevent *bev, void *ctx)
{
  struct bufferevent *
    partner = getpartner (bev, (pcallback_info) ctx);
  bufferevent_setcb (bev, readcb, NULL, eventcb, partner);
  bufferevent_setwatermark (bev, EV_WRITE, 0, 0);
  if (partner)
    bufferevent_enable (partner, EV_READ);
}

static void
close_on_finished_writecb (struct bufferevent *bev, void *ctx)
{
  struct evbuffer *
    b = bufferevent_get_output (bev);
  if (evbuffer_get_length (b) == 0)
    {
      bufferevent_free (bev);
    }
}

static void
eventcb (struct bufferevent *bev, short what, void *ctx)
{
  struct bufferevent *
    partner = getpartner (bev, (pcallback_info) ctx);

  if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
      if (what & BEV_EVENT_ERROR)
	{
	  if (errno)
	    perror ("connection error");
	}

      if (partner)
	{
	  /* Flush all pending data */
	  readcb (bev, ctx);

	  if (evbuffer_get_length (bufferevent_get_output (partner)))
	    {
	      /* We still have to flush data from the other
	       * side, but when that's done, close the other
	       * side. */
	      bufferevent_setcb (partner,
				 NULL, close_on_finished_writecb,
				 eventcb, NULL);
	      bufferevent_disable (partner, EV_READ);
	    }
	  else
	    {
	      /* We have nothing left to say to the other
	       * side; close it. */
	      bufferevent_free (partner);
	    }
	}
      bufferevent_free (bev);
    }
}

static void
syntax (void)
{
  fputs ("Syntax:\n", stderr);
  fputs
    ("   hppm [-l filename] [-r regexp] <listen-on-addr> <connect-to-addr>\n",
     stderr);
  fputs
    ("     -l - enables logging of all transit packets to file <filename>\n",
     stderr);
  fputs
    ("     -r - enables filtering of all data satisfied a POSIX regular expression <regexp>\n",
     stderr);
  fputs ("          all filtered data then will translated to stdout\n",
	 stderr);
  fputs ("Example:\n", stderr);
  fputs ("   hppm 127.0.0.1:8888 1.2.3.4:80\n", stderr);
  fputs ("   hppm -l log.txt -r [0-9a-f]{32} 127.0.0.1:1234 95.34.12.33:80\n",
	 stderr);
  exit (1);
}

static void
accept_cb (struct evconnlistener *listener, evutil_socket_t fd,
	   struct sockaddr *a, int slen, void *p)
{
  struct bufferevent *
  b_out, *
    b_in;
  pcallback_info
    pcbi;

  b_in = bufferevent_socket_new (base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);	// Clientside buffer
  b_out = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);	// Serverside buffer
  pcbi = (pcallback_info) malloc (sizeof (callback_info));
  assert (b_in && b_out);

  if (bufferevent_socket_connect
      (b_out, (struct sockaddr *) &connect_to_addr, connect_to_addrlen) < 0)
    {
      perror ("bufferevent_socket_connect");
      bufferevent_free (b_out);
      bufferevent_free (b_in);
      free (pcbi);
      return;
    }

  pcbi->client = b_in;
  pcbi->server = b_out;
  pcbi->session_id = (long) b_in;
  pcbi->packet_counter = 0;

  bufferevent_setcb (b_in, readcb, NULL, eventcb, pcbi);
  bufferevent_setcb (b_out, readcb, NULL, eventcb, pcbi);

  bufferevent_enable (b_in, EV_READ | EV_WRITE);
  bufferevent_enable (b_out, EV_READ | EV_WRITE);
}

int
main (int argc, char **argv)
{
  int
    i,
    socklen,
    erroffset,
    options = 0;
  pfilter_info
    pfi = NULL;
  pattern *
    p;
  struct evconnlistener *
    listener;
  const char *
    error;
  const unsigned char *
    re_tables = NULL;

  if (argc < 3)
    syntax ();

  for (i = 1; i < argc; ++i)
    {
      if (!strcmp (argv[i], "-l"))
	{
	  callback_info::logging = true;
	  ++i;
	  if (i > argc)
	    {
	      syntax ();
	      break;
	    }
	  strncpy (logfile, argv[i], MY_MAX_PATH);
	  logfile[MY_MAX_PATH - 1] = '\0';
	  printf ("Logging to: %s enabled\n", logfile);
	}
      else if (!strcmp (argv[i], "-r"))
	{
	  callback_info::filtering = true;
	  ++i;
	  if (i > argc)
	    {
	      syntax ();
	      break;
	    }
	  strncpy (regexp, argv[i], MY_MAX_PATH);
	  regexp[MY_MAX_PATH - 1] = '\0';
	  printf ("Regexp: %s added to filter chain\n", regexp);
	  if (!pfi)
	    {
	      pfi = (pfilter_info) malloc (sizeof (filter_info));
	      callback_info::pfi = pfi;
	      pfi->patterns = new std::vector < ppattern >;
	    }
	  p = new pattern;
	  p->raw_pattern = regexp;
	  re_tables = pcre_maketables ();
	  p->re = pcre_compile (regexp, options, &error, &erroffset, NULL);
	  p->extra_re = pcre_study (p->re, 0, &error);
	  if (!p->re || !p->extra_re)
	    syntax ();
	  callback_info::pfi->patterns->push_back (p);
	}
      else
	break;
    }

  if (i + 2 != argc)
    syntax ();

#ifdef WIN32
  WORD
    wVersionRequested;
  WSADATA
    wsaData;
  int
    err;
  wVersionRequested = MAKEWORD (2, 2);

  err = WSAStartup (wVersionRequested, &wsaData);
  if (err != 0)
    {
      printf ("WSAStartup failed with error: %d\n", err);
      return 1;
    }
#endif
  memset (&listen_on_addr, 0, sizeof (listen_on_addr));
  socklen = sizeof (listen_on_addr);
  if (evutil_parse_sockaddr_port (argv[i],
				  (struct sockaddr *) &listen_on_addr,
				  &socklen) < 0)
    {
      int
	p = atoi (argv[i]);
      struct sockaddr_in *
	sin = (struct sockaddr_in *) &listen_on_addr;
      if (p < 1 || p > 65535)
	syntax ();
      sin->sin_port = htons (p);
      sin->sin_addr.s_addr = htonl (0x7f000001);
      sin->sin_family = AF_INET;
      socklen = sizeof (struct sockaddr_in);
    }

  memset (&connect_to_addr, 0, sizeof (connect_to_addr));
  connect_to_addrlen = sizeof (connect_to_addr);
  if (evutil_parse_sockaddr_port (argv[i + 1],
				  (struct sockaddr *) &connect_to_addr,
				  &connect_to_addrlen) < 0)
    syntax ();

  if (callback_info::logging)
    {
      if (!(callback_info::fd_out = fopen (logfile, "wb")))
	{
	  syntax ();
	}

    }

  base = event_base_new ();
  if (!base)
    {
      perror ("event_base_new()");
      return 1;
    }

  listener = evconnlistener_new_bind (base, accept_cb, NULL,
				      LEV_OPT_CLOSE_ON_FREE |
				      LEV_OPT_CLOSE_ON_EXEC |
				      LEV_OPT_REUSEABLE, -1,
				      (struct sockaddr *) &listen_on_addr,
				      socklen);

  event_base_dispatch (base);

  if (callback_info::logging)
    {
      fclose (callback_info::fd_out);
    }

  if (callback_info::filtering)
    {
      callback_info::pfi->patterns->~vector ();
      free (callback_info::pfi);
    }

  evconnlistener_free (listener);
  event_base_free (base);

  return 0;
}
