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

#ifndef _LRADIUS_H
#define _LRADIUS_H

#ifndef LUARADIUS_API
#define LUARADIUS_API     LUA_API
#endif

#define LUARADIUS_PREFIX    "LuaRadius: "
#define LUARADIUS_CORENAME  "radius"
#define LUARADIUS_AUTHNAME  "radius.auth"
#define LUARADIUS_ACCTNAME  "radius.acct"

LUARADIUS_API int  luaradius_createmeta (lua_State *L, const char *name,
                                         const luaL_reg *methods);
LUARADIUS_API void luaradius_setmeta    (lua_State *L, const char *name);
LUARADIUS_API int  luaopen_radius       (lua_State *L);

#endif // _LRADIUS_H
