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

#ifndef _RADIUSCLIENT_H
#define _RADIUSCLIENT_H

typedef struct _RADIUSClientCtrl RADIUSClientCtrl;

enum {
  RADIUSCLIENT_ERR  =  0,
  RADIUSCLIENT_OK
};

enum {
  RADIUSCLIENT_AUTH_REQ = 0,
  RADIUSCLIENT_ACCT_REQ
};

/* RADIUS client API */
int  radclient_ctrl_init  (RADIUSClientCtrl *c);
void radclient_ctrl_free  (RADIUSClientCtrl *c);

int radclient_server_set (RADIUSClientCtrl *c, const char *hostname,
                          int port, const char *secret);
int radclient_attr_set   (RADIUSClientCtrl *c, const char *attr,
                          const char *value);
int radclient_attr_get   (RADIUSClientCtrl *c, const char *attr,
                          char *value, size_t value_size, const char **opr);

int radclient_send       (RADIUSClientCtrl *c, int packet_code);

void radclient_set_debug (RADIUSClientCtrl *c);

inline size_t radclient_ctrl_size (void);
inline const char *radclient_get_last_err_msg (RADIUSClientCtrl *c);

#endif /* _RADIUSCLIENT_H */
