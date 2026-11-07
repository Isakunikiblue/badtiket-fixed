<?php

use App\Http\Controllers\DashboardController;
use Illuminate\Support\Facades\Route;

Route::get('/', [DashboardController::class, 'index'])->name('home');
Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
Route::post('/mata-api/sync-data', [DashboardController::class, 'syncData'])->name('api.sync');
Route::get('/mata-api/dashboard-data', [DashboardController::class, 'getData'])->name('api.data');

// Fallback aliases
Route::post('/api/sync-data', [DashboardController::class, 'syncData']);
Route::get('/api/dashboard-data', [DashboardController::class, 'getData']);
