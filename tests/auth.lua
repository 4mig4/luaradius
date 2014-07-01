require 'radius'

assert (radius.auth, "radius.auth is unavailable");

local auth = radius.auth.new ();
local res  = 0;
local msg  = "";
local attr = {};

assert (auth, "No authen instance created");

auth:enableDebug ();

auth:setServer ("127.0.0.1", 0, "testing123");
auth:setUsername ("test");
auth:setPassword ("hello");

auth:setAttribute ("NAS-IP-Address", "192.168.122.100");
auth:setAttribute ("NAS-Port", "1");
auth:setAttribute ("Auth-Type", "PAP");

res = auth:send ();

if res == 1 then
  msg = "OK";
else
  msg = "Failed: " .. auth:getLastErrMsg ();
end

print ("\nTest Result: " .. msg);

attr = auth:getAttribute ("WISPr-Bandwidth-Max-Up");
if attr ~= nil then
  print (attr.name .. " " .. attr.opr .. " " .. attr.value);
end

attr = auth:getAttribute ("Reply-Message");
if attr ~= nil then
  print (attr.name .. " " .. attr.opr .. " " .. attr.value);
end
