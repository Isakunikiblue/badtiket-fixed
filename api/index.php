<?php

// Pastikan direktori writable /tmp tersedia untuk lingkungan Vercel Serverless
if (isset($_SERVER['VERCEL']) || isset($_ENV['VERCEL'])) {
    $dirs = [
        '/tmp/storage/framework/views',
        '/tmp/storage/framework/cache/data',
        '/tmp/storage/framework/sessions',
        '/tmp/storage/logs',
        '/tmp/bootstrap/cache',
    ];
    foreach ($dirs as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
    }
}

// Forward Vercel serverless requests to Laravel's public index.php
require __DIR__ . '/../public/index.php';
