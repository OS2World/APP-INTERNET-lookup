uses os2base, os2def, use32, sock, strstf, strings;

var
  host: phostent;
  buf: array[0..256] of char;
  addr: string;
  ip: ulong;

begin
  if paramcount=0 then
    begin
      writeln('usage: lookup [ip/domain]');
      halt(-1);
    end;
  addr:=truncstr(paramstr(1));
  sock_init;
  fillchar(host, sizeof(host), #0);
  if not isip(addr) then host:=gethostbyname(strpcopy(buf, addr)) else
    begin
      ip:=inet_ston(addr);
      host:=gethostbyaddr(@ip, sizeof(ulong), AF_INET);
    end;

  if host=nil then
    begin
      writeln('unable to look up: '+addr);
      halt(-1);
    end;
  if isip(addr) then
    writeln('*** 0F'+addr+' 03resolved to: 0B', host^.h_name, '07')
  else
    begin
      move(host^.h_addr_list^^, ip, host^.h_length);
      writeln('*** 0F'+addr+' 03resolved to: 0B'+inet_ntos(ip), '07');
    end;
end.

