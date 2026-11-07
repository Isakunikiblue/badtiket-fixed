<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Resend, Postmark, AWS, and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'key' => env('POSTMARK_API_KEY'),
    ],

    'resend' => [
        'key' => env('RESEND_API_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    'google_sheets' => [
        'spreadsheet_id' => env('GOOGLE_SPREADSHEET_ID'),
        'webapp_url' => env('GOOGLE_SHEET_WEBAPP_URL', 'https://script.google.com/macros/s/AKfycbzsATpz5NB3a6LXaeilqp0cBiIBigCwp5hPzvo88kJqLtEZN8fmp_bZW8Xy-G7KEJJ5/exec'),
        'cache_ttl' => env('GOOGLE_SHEETS_CACHE_TTL', 180),
    ],

];
