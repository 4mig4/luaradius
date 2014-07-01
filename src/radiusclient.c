/**
 * Copyright (C) 2012  Neutron Soutmun <neo.neutron@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <freeradius/ident.h>
#include <freeradius/libradius.h>
#include <freeradius/conf.h>
#include <freeradius/radpaths.h>
#include <poll.h>
#include "radiusclient.h"

struct _RADIUSClientCtrl {
  RADIUS_PACKET *request;
  RADIUS_PACKET *reply;
  fr_ipaddr_t    server_ipaddr;
  fr_ipaddr_t    client_ipaddr;
  int    server_port;
  int    client_port;
  int    packet_code;
  char   secret[256];
  int    sockfd;
  int    packet_number;
  char   password[256];
  int    done;
  float  timeout;
  int    force_af;
  time_t timestamp;
  int    debug;
  const char *radius_dir;
  const char *lastErrMsg;
  char   errMsgBuf[1024];
};

/* Internal declaration */

static int  getport (const char *name);
static void print_hex (RADIUS_PACKET *packet);

/**
 * This is a hack, and has to be kept in sync with FreeRADIUS - tokens.h
 **/
static const char *vp_tokens[] = {
  "?",        /* T_OP_INVALID */
  "EOL",      /* T_EOL */
  "{",
  "}",
  "(",
  ")",
  ",",
  ";",
  "+=",
  "-=",
  ":=",
  "=",
  "!=",
  ">=",
  ">",
  "<=",
  "<",
  "=~",
  "!~",
  "=*",
  "!*",
  "==",
  "#",
  "<BARE-WORD>",
  "<\"STRING\">",
  "<'STRING'>",
  "<`STRING`>"
};

/* Implementation */

int
radclient_ctrl_init (RADIUSClientCtrl *c)
{
  if (!c)
    return RADIUSCLIENT_ERR;

  memset (c, 0, sizeof (RADIUSClientCtrl));

  c->request = rad_alloc (1);
  c->reply   = NULL; 
  c->timeout = 5000;
  c->sockfd  = -1;
  c->done    = 1;
  c->radius_dir   = RADDBDIR;
  c->force_af     = AF_INET;
  c->secret[0]    = '\0'; 
  c->debug        = 0;
  c->lastErrMsg   = "No errors";
  c->errMsgBuf[0] = '\0';

  if (dict_init (c->radius_dir, RADIUS_DICTIONARY) < 0)
    {
      c->lastErrMsg = "Initializing dictionary failed";
      return RADIUSCLIENT_ERR;
    }

  return RADIUSCLIENT_OK;
}

void
radclient_ctrl_free (RADIUSClientCtrl *c)
{
  if (c->request)
    rad_free (&c->request);

  if (c->reply)
    rad_free (&c->reply);

  dict_free ();
}

int
radclient_server_set (RADIUSClientCtrl *c, const char *hostname, int port,
                      const char *secret)
{
  char buffer[256];
  const char *host = NULL;
  const char *p = NULL;

  if (!c)
    return RADIUSCLIENT_ERR;

  host = hostname;

  if (hostname[1] == '[') /* IPv6 URL encoded */
    {
      p = strchr (hostname, ']');

      if ((size_t) (p - hostname) >= sizeof (buffer))
        return RADIUSCLIENT_ERR;

      memcpy (buffer, hostname + 1, p - hostname - 1);
      buffer[p - hostname - 1] = '\0';

      host = buffer;
    }

  if (ip_hton (host, c->force_af, &c->request->dst_ipaddr) < 0)
    {
      c->lastErrMsg = "Invalid hostname or IP";
      return RADIUSCLIENT_ERR;
    }

  if (port > 0)
    c->request->dst_port = port;

  if (secret)
    strncpy (c->secret, secret, sizeof (c->secret));

  return RADIUSCLIENT_OK;
}

int
radclient_attr_set (RADIUSClientCtrl *c, const char *attr, const char *value)
{
  VALUE_PAIR *vp = NULL;

  if (!c)
    return RADIUSCLIENT_ERR;

  if (!attr || !value)
    {
      c->lastErrMsg = "Invalid arguments";
      return RADIUSCLIENT_ERR;
    }

  vp = pairmake (attr, value, T_OP_EQ);

  if (vp)
    pairadd (&c->request->vps, vp);
  else
    /* Silently ignore the invalid attribute-value pair */

  return RADIUSCLIENT_OK;
}

int
radclient_attr_get (RADIUSClientCtrl *c, const char *attr,
                    char *value, size_t value_size, const char **opr)
{
  VALUE_PAIR *vpfind = NULL;
  VALUE_PAIR *vp = NULL;

  if (!c)
    return RADIUSCLIENT_ERR;

  if (!attr || !value || !opr)
    {
      c->lastErrMsg = "Invalid arguments";
      return RADIUSCLIENT_ERR;
    }

  if (!c->reply)
    {
      c->lastErrMsg = "No reply";
      return RADIUSCLIENT_ERR;
    }

  vpfind = pairmake (attr, "", T_OP_EQ);

  if (!vpfind)
    {
      c->lastErrMsg = "Invalid attribute";
      return RADIUSCLIENT_ERR;
    }

  vp = pairfind (c->reply->vps, vpfind->attribute); 

  if (!vp)
    {
      c->lastErrMsg = "Attribute not found";
      goto fail;
    }

  if ((vp->operator > T_OP_INVALID) && (vp->operator < T_TOKEN_LAST))
    *opr = vp_tokens[vp->operator];
  else
    *opr = "<INVALID-TOKEN>";

  if (vp_prints_value (value, value_size, vp, 0) <= 0)
    {
      c->lastErrMsg = "Could not get value";
      goto fail;
    }

  if (c->debug)
    {
      fprintf (stdout, "Get attribute: %s %s %s\n", attr, *opr, value);
    }

  pairfree (&vpfind);
  return RADIUSCLIENT_OK;

fail:
  pairfree (&vpfind);
  return RADIUSCLIENT_ERR;
}

int
radclient_send (RADIUSClientCtrl *c, int packet_code)
{
  int i;
  int rcode;
  struct pollfd pfd;

  if (!c)
    return RADIUSCLIENT_ERR;

  /* Send */
  memset (&c->request->src_ipaddr, 0, sizeof (c->request->src_ipaddr));
  c->request->src_ipaddr.af = c->force_af;
  c->request->src_port = 0;

  c->sockfd = fr_socket (&c->request->src_ipaddr, c->request->src_port);

  if (c->sockfd < 0)
    {
      c->lastErrMsg = "Could not create new socket";
      return RADIUSCLIENT_ERR;
    }

  for (i = 0; i < 4; i++)
    {
      ((uint32_t *) c->request->vector)[i] = fr_rand ();
    }

  c->packet_code = packet_code == RADIUSCLIENT_AUTH_REQ ?
                     PW_AUTHENTICATION_REQUEST :
                     PW_ACCOUNTING_REQUEST;

  if (c->packet_code == PW_AUTHENTICATION_REQUEST)
    {
      c->request->dst_port = getport ("radius");
      if (c->request->dst_port == 0)
        c->request->dst_port = PW_AUTH_UDP_PORT;
    }
  else
    {
      c->request->dst_port = getport ("radacct");
      if (c->request->dst_port == 0)
        c->request->dst_port = PW_ACCT_UDP_PORT;
    }

  c->request->code   = c->packet_code;

  c->request->id = (int) fr_rand () & 0xff;
  c->request->sockfd = c->sockfd;

  if (rad_send (c->request, NULL, c->secret) < 0)
    {
      snprintf (c->errMsgBuf, sizeof (c->errMsgBuf) - 1,
                "Failed to send packet: %s", fr_strerror ());
      c->errMsgBuf[sizeof (c->errMsgBuf) - 1] = '\0';
      c->lastErrMsg = c->errMsgBuf;
      goto fail;
    }

  if (c->debug)
    {
      fprintf (stdout, "=== Sent =======\n");
      print_hex (c->request);
    }

  /* Receive */
  pfd.fd = c->sockfd;
  pfd.events = POLLIN;
  
  if (poll (&pfd, 1, c->timeout) <= 0)
    {
      c->lastErrMsg = "Socket error or timeout";
      goto fail;
    }

  c->reply = rad_recv (c->sockfd, 0);
  if (!c->reply)
    {
      c->lastErrMsg = "Reply packet is invalid";
      goto fail;
    }

  if (rad_verify (c->reply, c->request, c->secret) < 0)
    {
      c->lastErrMsg = "Failed to verify reply packet";
      goto fail;
    }

  if (rad_decode (c->reply, c->request, c->secret) < 0)
    {
      c->lastErrMsg = "Failed to decode reply packet";
      goto fail;
    }

  if (c->debug)
    {
      fprintf (stdout, "=== Received ===\n");
      print_hex (c->reply);
      fprintf (stdout, "=== Reply ======\n");
      vp_printlist (stdout, c->reply->vps);
    }

  if ((c->reply->code == PW_AUTHENTICATION_ACK) ||
      (c->reply->code == PW_ACCOUNTING_RESPONSE) ||
      (c->reply->code == PW_COA_ACK) ||
      (c->reply->code == PW_DISCONNECT_ACK))
    {
      close (c->sockfd);
      return RADIUSCLIENT_OK;
    }

fail:
  close (c->sockfd);
  return RADIUSCLIENT_ERR;
}

void
radclient_set_debug (RADIUSClientCtrl *c)
{
  if (!c)
    return;

  c->debug = 1;
}

inline size_t
radclient_ctrl_size  (void)
{
  return sizeof (RADIUSClientCtrl);
}

inline const char *
radclient_get_last_err_msg (RADIUSClientCtrl *c)
{
  if (!c)
    return "";

  return c->lastErrMsg;
}

/* Internal implementation */

static int
getport (const char *name)
{
  struct servent *svp = NULL;

  svp = getservbyname (name, "udp");
  if (!svp)
    return 0;

  return ntohs (svp->s_port);
}

static void
print_hex (RADIUS_PACKET *packet)
{
	int i;

	if (!packet->data) return;

	printf("  Code:\t\t%u\n", packet->data[0]);
	printf("  Id:\t\t%u\n", packet->data[1]);
	printf("  Length:\t%u\n", ((packet->data[2] << 8) |
				   (packet->data[3])));
	printf("  Vector:\t");
	for (i = 4; i < 20; i++) {
		printf("%02x", packet->data[i]);
	}
	printf("\n");

	if (packet->data_len > 20) {
		int total;
		const uint8_t *ptr;
		printf("  Data:");

		total = packet->data_len - 20;
		ptr = packet->data + 20;

		while (total > 0) {
			int attrlen;

			printf("\t\t");
			if (total < 2) { /* too short */
				printf("%02x\n", *ptr);
				break;
			}

			if (ptr[1] > total) { /* too long */
				for (i = 0; i < total; i++) {
					printf("%02x ", ptr[i]);
				}
				break;
			}

			printf("%02x  %02x  ", ptr[0], ptr[1]);
			attrlen = ptr[1] - 2;
			ptr += 2;
			total -= 2;

			for (i = 0; i < attrlen; i++) {
				if ((i > 0) && ((i & 0x0f) == 0x00))
					printf("\t\t\t");
				printf("%02x ", ptr[i]);
				if ((i & 0x0f) == 0x0f) printf("\n");
			}

			if ((attrlen & 0x0f) != 0x00) printf("\n");

			ptr += attrlen;
			total -= attrlen;
		}
	}
	fflush(stdout);
}
