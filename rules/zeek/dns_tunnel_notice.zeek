# Zeek notice — long DNS query heuristic (tunneling signal). Zeek 4+ DNS::log_policy hook.
@load base/frameworks/notice
@load base/protocols/dns

module DNS_Tunnel_Lab;

export {
    redef enum Notice::Type += { DNS_Tunnel_LongQuery_Lab };
    const min_query_len: count = 60 &redef;
}

hook DNS::log_policy(rec: DNS::Info)
    {
    if ( rec?$query && |rec$query| >= min_query_len )
        {
        NOTICE([$note=DNS_Tunnel_LongQuery_Lab,
                $msg=fmt("Long DNS query (lab): %s", rec$query),
                $identifier=rec$query]);
        }
    }
