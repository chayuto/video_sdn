
@load frameworks/communication/listen
redef Communication::listen_port = 47758/tcp;

redef Communication::nodes += {
	["broping"] = [$host = 127.0.0.1, $events = /test1|test3|test5/, $connect=F, $ssl=F]
};

global test2: event(a: int, b: count, c: time, d: interval, e: bool, f: double, g: string, h: port, i: addr, j: subnet, i6: addr, j6: subnet);

event new_connection(c: connection ){
    
    print c$id$orig_h;
    print port_to_count(c$id$orig_p);
    print c$id$resp_h;
    print port_to_count(c$id$resp_p);
    print get_port_transport_proto(c$id$resp_p);

    event test2(-4, 42, current_time(), 1min, T, 3.14, "Hurz", 12345/udp, 1.2.3.4, 22.33.44.0/24, [2607:f8b0:4009:802::1014], [2607:f8b0:4009:802::1014]/32);
}
