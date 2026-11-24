<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\View;

class SecurityHeadersMiddleware
{
    /**
     * Handle an incoming request and enforce strict security headers.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Generate cryptographic CSP Nonce per-request
        $nonce = base64_encode(random_bytes(16));
        View::share('cspNonce', $nonce);

        // 2. Matikan leak informasi versi PHP (X-Powered-By)
        if (function_exists('header_remove')) {
            @header_remove('X-Powered-By');
            @header_remove('Server');
        }
        @ini_set('expose_php', 'off');

        $response = $next($request);

        // 3. Anti-Clickjacking & Anti-MIME Sniffing & HSTS & CORS
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
        $response->headers->set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
        $response->headers->set('Access-Control-Allow-Origin', 'https://dashboard-mata.vercel.app');

        // 4. Content Security Policy (CSP) Lengkap & Ketat
        // Mengeliminasi wildcard (img-src https:), unsafe-eval, dan unsafe-inline via nonce & CSP level 3
        $csp = "default-src 'self' https://script.google.com https://script.googleusercontent.com; " .
               "script-src 'self' 'nonce-{$nonce}' https://script.google.com; " .
               "script-src-attr 'unsafe-inline'; " .
               "style-src 'self' 'nonce-{$nonce}'; " .
               "style-src-attr 'unsafe-inline'; " .
               "font-src 'self' data:; " .
               "img-src 'self' data: blob: https://script.google.com https://script.googleusercontent.com https://lh3.googleusercontent.com; " .
               "connect-src 'self' https://script.google.com https://script.googleusercontent.com https://api.telegram.org; " .
               "frame-ancestors 'self'; " .
               "base-uri 'self'; " .
               "form-action 'self';";
        $response->headers->set('Content-Security-Policy', $csp);

        // 5. Anti-Caching untuk mencegah bocornya data sensitif di proxy/browser cache
        $response->headers->set('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Expires', '0');

        // 6. Hapus header X-Powered-By dan Server dari Symfony Response
        $response->headers->remove('X-Powered-By');
        $response->headers->remove('Server');

        // 7. Pastikan seluruh Cookie memiliki atribut Secure, HttpOnly, dan SameSite=Lax
        foreach ($response->headers->getCookies() as $cookie) {
            $response->headers->setCookie(
                $cookie->withSecure(true)->withHttpOnly(true)->withSameSite('Lax')
            );
        }

        return $response;
    }
}
