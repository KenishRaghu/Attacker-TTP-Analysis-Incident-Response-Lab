# Zeek — HTTP GET with staging path (lab C2 pattern). Zeek 4+ HTTP events.
@load base/frameworks/notice
@load base/protocols/http

module HTTP_C2_Lab;

export {
    redef enum Notice::Type += { HTTP_Stager_URI_Lab };
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( method == "GET" && /\/stage2\.bin/ in unescaped_URI )
        {
        NOTICE([$note=HTTP_Stager_URI_Lab,
                $msg=fmt("Possible HTTP stager URI: %s", unescaped_URI),
                $conn=c, $identifier=cat(c$id$resp_h, unescaped_URI)]);
        }
    }
