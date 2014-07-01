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

#include <lua.h>
#include <lauxlib.h>
#include "lradius.h"
#include "radiusclient.h"

/**
 * LUA Helper
 */

static void setfield (lua_State *L, const char *index, const char *value);

/**
 * LUA RADIUS API
 */


static int  lradius_server_set (lua_State *L, const char *name);
static int  lradius_attr_set   (lua_State *L, const char *name);
static int  lradius_attr_get   (lua_State *L, const char *name);
static void lradius_cleanup    (lua_State *L);

static int
lradius_server_set (lua_State *L, const char *name)
{
  RADIUSClientCtrl *c  = NULL;
  const char *hostname = luaL_checkstring (L, 2);
  int         port     = lua_tointeger (L, 3);
  const char *secret   = luaL_checkstring (L, 4);

  if (!name)
    return 0;

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, name);

  lua_pushinteger (L, 1);

  return radclient_server_set (c, hostname, port, secret);
}

static int
lradius_attr_set (lua_State *L, const char *name)
{
  RADIUSClientCtrl *c  = NULL;
  const char *attr  = luaL_checkstring (L, 2);
  const char *value = luaL_checkstring (L, 3);

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, name);

  return radclient_attr_set (c, attr, value);
}

static int
lradius_attr_get (lua_State *L, const char *name)
{
  RADIUSClientCtrl *c  = NULL;
  const char *attr = luaL_checkstring (L, 2);
  char value[1024];
  const char *opr  = NULL;

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, name);

  if (radclient_attr_get (c, attr, value,
        sizeof (value), &opr) == RADIUSCLIENT_OK)
    {
      lua_newtable (L);
      setfield (L, "name", attr);
      setfield (L, "opr", opr);
      setfield (L, "value", value);
    }
  else
    {
      lua_pushnil (L);
    }

  return 1;
}

static void
lradius_cleanup (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_AUTHNAME);

  radclient_ctrl_free (c);
}

/**
 * AUTH API
 */

static RADIUSClientCtrl *
auth_pnew (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;

  c = (RADIUSClientCtrl *)lua_newuserdata (L, radclient_ctrl_size ());
  if (radclient_ctrl_init (c) == RADIUSCLIENT_ERR)
    return NULL;

  luaL_getmetatable (L, LUARADIUS_AUTHNAME);
  lua_setmetatable (L, -2);
  return c;
}

static int
auth_fnew (lua_State *L)
{
  RADIUSClientCtrl *c = auth_pnew (L);

  if (!c)
    return 0;

  return 1;
}

static int
auth_fauth (lua_State *L)
{
  return 1;
}

static int
auth_server_set (lua_State *L)
{
  return lradius_server_set (L, LUARADIUS_AUTHNAME);
}

static int
auth_attr_set (lua_State *L)
{
  return lradius_attr_set (L, LUARADIUS_AUTHNAME);
}

static int
auth_attr_get (lua_State *L)
{
  return lradius_attr_get (L, LUARADIUS_AUTHNAME);
}

static int
auth_username_set (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  const char *username = luaL_checkstring (L, 2);

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_AUTHNAME);

  return radclient_attr_set (c, "User-Name", username);
}

static int
auth_password_set (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  const char *passwd = luaL_checkstring (L, 2);

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_AUTHNAME);

  return radclient_attr_set (c, "User-Password", passwd);
}

static int
auth_send (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  int res = RADIUSCLIENT_ERR;

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_AUTHNAME);

  res = radclient_send (c, RADIUSCLIENT_AUTH_REQ);

  if (res == RADIUSCLIENT_OK)
    lua_pushinteger (L, 1);
  else
    lua_pushinteger (L, 0);

  return 1;
}

static int
auth_en_debug (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_AUTHNAME);

  radclient_set_debug (c);

  return 1;
}

static int
auth_get_last_err_msg (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_AUTHNAME);

  lua_pushstring (L, radclient_get_last_err_msg (c));

  return 1;
}

static int
auth_gc (lua_State *L)
{
  lradius_cleanup (L);
  return 1;
}

/**
 * ACCT API
 */

static RADIUSClientCtrl *
acct_pnew (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;

  c = (RADIUSClientCtrl *)lua_newuserdata (L, radclient_ctrl_size ());
  radclient_ctrl_init (c);

  luaL_getmetatable (L, LUARADIUS_ACCTNAME);
  lua_setmetatable (L, -2);
  return c;
}

static int
acct_fnew (lua_State *L)
{
  RADIUSClientCtrl *c = acct_pnew (L);

  if (!c)
    return 0;

  return 1;
}

static int
acct_facct (lua_State *L)
{
  return 1;
}

static int
acct_server_set (lua_State *L)
{
  return lradius_server_set (L, LUARADIUS_ACCTNAME);
}

static int
acct_username_set (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  const char *username = luaL_checkstring (L, 2);

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_ACCTNAME);

  return radclient_attr_set (c, "User-Name", username);
}

static int
acct_attr_set (lua_State *L)
{
  return lradius_attr_set (L, LUARADIUS_ACCTNAME);
}

static int
acct_send (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  int res = RADIUSCLIENT_ERR;

  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_ACCTNAME);

  res = radclient_send (c, RADIUSCLIENT_ACCT_REQ);

  if (res == RADIUSCLIENT_OK)
    lua_pushinteger (L, 1);
  else
    lua_pushinteger (L, 0);

  return 1;
}

static int
acct_en_debug (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_ACCTNAME);

  radclient_set_debug (c);

  return RADIUSCLIENT_OK;
}

static int
acct_get_last_err_msg (lua_State *L)
{
  RADIUSClientCtrl *c = NULL;
  c = (RADIUSClientCtrl *)luaL_checkudata (L, 1, LUARADIUS_ACCTNAME);

  lua_pushstring (L, radclient_get_last_err_msg (c));

  return 1;
}

static int
acct_gc (lua_State *L)
{
  lradius_cleanup (L);
  return 1;
}

/**
 * Lua Initailize
 */

LUARADIUS_API int
luaradius_createmeta (lua_State *L, const char *name, const luaL_reg *methods)
{
  if (!luaL_newmetatable (L, name))
    return 0;

  luaL_openlib (L, NULL, methods, 0);

  lua_pushliteral (L, "__index");
  lua_pushvalue (L, -2);
  lua_settable (L, -3);

  lua_pushliteral (L, "__metatable");
  lua_pushliteral (L, LUARADIUS_PREFIX"you're not allowed to get this "
                   "metatable");
  lua_settable (L, -3);

  return 1;
}

LUARADIUS_API void
luaradius_setmeta (lua_State *L, const char *name)
{
  luaL_getmetatable (L, name);
  lua_setmetatable (L, -2);
}

static void
create_call_table (lua_State *L, const char *name, lua_CFunction creator,
                   lua_CFunction starter)
{
  lua_createtable (L, 0, 1);
  lua_pushcfunction (L, creator);
  lua_setfield (L, -2, "new");

  lua_createtable (L, 0, 1);
  lua_pushcfunction (L, starter);
  lua_setfield (L, -2, "__call");
  lua_setmetatable (L, -2);
  lua_setfield (L, -2, name); 
}

static void
create_metatables (lua_State *L)
{
  struct luaL_reg core_functions[] = {
    { NULL, NULL }
  };

  struct luaL_reg auth_methods[] = {
    { "__gc", auth_gc },
    { "setServer", auth_server_set },
    { "setUsername", auth_username_set },
    { "setPassword", auth_password_set },
    { "setAttribute", auth_attr_set },
    { "getAttribute", auth_attr_get },
    { "send", auth_send },
    { "enableDebug", auth_en_debug },
    { "getLastErrMsg", auth_get_last_err_msg }, 
    { NULL, NULL }
  };

  struct luaL_reg acct_methods[] = {
    { "__gc", acct_gc },
    { "setServer", acct_server_set },
    { "setUsername", acct_username_set },
    { "setAttribute", acct_attr_set },
    { "send", acct_send },
    { "enableDebug", acct_en_debug },
    { "getLastErrMsg", acct_get_last_err_msg },
    { NULL, NULL }
  };

  luaL_register (L, LUARADIUS_CORENAME, core_functions);

#define CALLTABLE(n) create_call_table (L, #n, n##_fnew, n##_f##n)
  CALLTABLE(auth);
  CALLTABLE(acct);

  luaradius_createmeta (L, LUARADIUS_AUTHNAME, auth_methods);
  luaradius_createmeta (L, LUARADIUS_ACCTNAME, acct_methods);

  lua_pop (L, 3);
}

LUARADIUS_API int
luaopen_radius (lua_State *L)
{
  struct luaL_reg core[] = {
    {NULL, NULL},
  };

  create_metatables (L);
  luaL_openlib (L, LUARADIUS_CORENAME, core, 0);
  
  return 1;
}

/**
 * LUA Helper implementation
 */
static void
setfield (lua_State *L, const char *index, const char *value)
{
  lua_pushstring (L, index);
  lua_pushstring (L, value);
  lua_settable (L, -3);
}
