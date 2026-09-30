// Goal 21: CloudFront viewer-request function for solomonsdigital.com.au (cloudfront-js-2.0).
// GENERATED on every deploy by .github/edge/build_edge.py from the deploy repo: do not edit the live copy.
// "/"                  -> 301 to the firm website (Nicole 2026-09-24)
// "/<slug>"            -> 301 to "/<slug>/" (published cards only)
// "/<slug>/"           -> "/<slug>/index.html" from the private bucket
// a published file     -> served from the bucket
// ANYTHING ELSE        -> the card-not-found page, answered HERE with the full security headers (Daniel's audit F16:
//                         CloudFront adds no function headers to the bucket's own error responses, so unknown
//                         addresses never reach the bucket)
// any other host       -> 301 to the same path on solomonsdigital.com.au (Phase 8 item 8)
// Responses made here skip the viewer-response function, so they carry the SAME header set themselves.
var SECURITY_HEADERS = {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    'x-robots-tag': 'noindex, nofollow, noarchive',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    'cross-origin-opener-policy': 'same-origin'
};
var PUBLISHED = /*PUBLISHED*/{};
var NOT_FOUND_HTML = /*NOT_FOUND_HTML*/'';

function headers(extra) {
    var h = {};
    for (var k in SECURITY_HEADERS) {
        h[k] = { value: SECURITY_HEADERS[k] };
    }
    for (var e in extra) {
        h[e] = { value: extra[e] };
    }
    return h;
}

function redirect(location) {
    return { statusCode: 301, statusDescription: 'Moved Permanently', headers: headers({ location: location }) };
}

function notFound() {
    return { statusCode: 404, statusDescription: 'Not Found',
             headers: headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=60' }),
             body: NOT_FOUND_HTML };
}

function handler(event) {
    var req = event.request;
    var uri = req.uri;
    var host = req.headers.host ? req.headers.host.value.toLowerCase() : '';
    if (host !== 'solomonsdigital.com.au') {
        return redirect('https://solomonsdigital.com.au' + uri);
    }
    if (uri === '/' || uri === '') {
        return redirect('https://thesolomons.com.au/');
    }
    if (uri.endsWith('/')) {
        var index = uri.substring(1) + 'index.html';
        if (PUBLISHED[index]) {
            req.uri = uri + 'index.html';
            return req;
        }
        return notFound();
    }
    var last = uri.substring(uri.lastIndexOf('/') + 1);
    if (last.indexOf('.') === -1) {
        return PUBLISHED[uri.substring(1) + '/index.html'] ? redirect(uri + '/') : notFound();
    }
    return PUBLISHED[uri.substring(1)] ? req : notFound();
}
