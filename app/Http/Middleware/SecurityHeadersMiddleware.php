<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeadersMiddleware
{
    /**
     * Handle an incoming request and enforce strict security headers.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Matikan leak informasi versi PHP (X-Powered-By)
        if (function_exists('header_remove')) {
            @header_remove('X-Powered-By');
            @header_remove('Server');
        }
        @ini_set('expose_php', 'off');

        $response = $next($request);

        // 2. Anti-Clickjacking & Anti-MIME Sniffing
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');

        // 3. Content Security Policy (CSP) Lengkap & Ketat
        $csp = "default-src 'self' https://script.google.com https://script.googleusercontent.com; " .
               "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " .
               "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; " .
               "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; " .
               "img-src 'self' data: blob: https:; " .
               "connect-src 'self' https://script.google.com https://script.googleusercontent.com https://api.telegram.org; " .
               "frame-ancestors 'self'; " .
               "base-uri 'self'; " .
               "form-action 'self';";
        $response->headers->set('Content-Security-Policy', $csp);

        // 4. Anti-Caching untuk mencegah bocornya data sensitif di proxy/browser cache
        $response->headers->set('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Expires', '0');

        // 5. Hapus header X-Powered-By dari Symfony Response
        $response->headers->remove('X-Powered-By');
        $response->headers->remove('Server');

        // 6. Pastikan seluruh Cookie memiliki atribut Secure, HttpOnly, dan SameSite=Lax
        foreach ($response->headers->getCookies() as $cookie) {
            $response->headers->setCookie(
                $cookie->withSecure(true)->withHttpOnly(true)->withSameSite('Lax')
            );
        }

        return $response;
    }
}
