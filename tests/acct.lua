require 'radius'

assert (radius.acct, "radius.acct is unavailable");

local acct = radius.acct.new ();
local res  = 0;
local msg  = "";

assert (acct, "No accounting instance created");

acct:enableDebug ();

acct:setServer ("127.0.0.1", 0, "testing123");
acct:setUsername ("test");

acct:setAttribute ("Acct-Status-Type", "Start");
acct:setAttribute ("Acct-Session-Time", 600);
acct:setAttribute ("NAS-IP-Address", "192.168.122.100");
acct:setAttribute ("NAS-Port", "1");

res = acct:send ();

if res == 1 then
  msg = "OK";
else
  msg = "Failed:" .. acct:getLastErrMsg ();
end

print ("\nTest Result: " .. msg);
