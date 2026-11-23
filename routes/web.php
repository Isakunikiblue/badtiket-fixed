<?php

use App\Http\Controllers\DashboardController;
use App\Http\Controllers\GasBridgeController;
use Illuminate\Support\Facades\Route;

Route::get('/', [DashboardController::class, 'index'])->name('home');
Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');

Route::get('/robots.txt', function () {
    return response("User-agent: *\nDisallow: /\n", 200, ['Content-Type' => 'text/plain']);
});

Route::get('/sitemap.xml', function () {
    return response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 200, ['Content-Type' => 'application/xml']);
});

// Rute API & RPC dilindungi oleh Rate Limiter untuk mitigasi DDoS / Credential Flooding
Route::middleware('throttle:120,1')->group(function () {
    Route::post('/mata-api/sync-data', [DashboardController::class, 'syncData'])->name('api.sync');
    Route::get('/mata-api/dashboard-data', [DashboardController::class, 'getData'])->name('api.data');
    Route::match(['GET', 'POST'], '/mata-api/rpc', [GasBridgeController::class, 'handleRpc'])->name('api.rpc');

    // Fallback aliases
    Route::post('/api/sync-data', [DashboardController::class, 'syncData']);
    Route::get('/api/dashboard-data', [DashboardController::class, 'getData']);
    Route::match(['GET', 'POST'], '/api/rpc', [GasBridgeController::class, 'handleRpc']);
});
