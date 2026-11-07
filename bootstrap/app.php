<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

$app = Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->validateCsrfTokens(except: [
            'api/*',
            'mata-api/*',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->is('mata-api/*') || $request->expectsJson(),
        );
    })->create();

// Support for Serverless Environments (e.g. Vercel)
if (isset($_SERVER['VERCEL']) || isset($_ENV['VERCEL'])) {
    $storagePath = '/tmp/storage';
    $app->useStoragePath($storagePath);
    $dirs = ['framework/views', 'framework/cache', 'framework/sessions', 'logs'];
    foreach ($dirs as $dir) {
        $fullPath = $storagePath . '/' . $dir;
        if (!is_dir($fullPath)) {
            @mkdir($fullPath, 0777, true);
        }
    }
}

return $app;
