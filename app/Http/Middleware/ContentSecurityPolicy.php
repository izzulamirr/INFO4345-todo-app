<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ContentSecurityPolicy
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

    $response->headers->set(
       'Content-Security-Policy',
        "default-src 'self'; " .
        "script-src 'self' https://cdn.jsdelivr.net; " .
        "style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net; " .
        "font-src 'self' https://fonts.gstatic.com; " .
        "img-src 'self' data:;"
    );
        return $response;
    }
}
