<?php

use App\Http\Controllers\DashboardController;
use App\Http\Controllers\GasBridgeController;
use Illuminate\Support\Facades\Route;

Route::get('/', [DashboardController::class, 'index'])->name('home');
Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
Route::post('/mata-api/sync-data', [DashboardController::class, 'syncData'])->name('api.sync');
Route::get('/mata-api/dashboard-data', [DashboardController::class, 'getData'])->name('api.data');

// RPC endpoint untuk melayani seluruh panggilan bridge google.script.run tanpa kendala CORS
Route::match(['GET', 'POST'], '/mata-api/rpc', [GasBridgeController::class, 'handleRpc'])->name('api.rpc');

// Fallback aliases
Route::post('/api/sync-data', [DashboardController::class, 'syncData']);
Route::get('/api/dashboard-data', [DashboardController::class, 'getData']);
Route::match(['GET', 'POST'], '/api/rpc', [GasBridgeController::class, 'handleRpc']);
