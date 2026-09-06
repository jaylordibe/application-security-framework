<?php

// PUBLIC: no authentication middleware anywhere above it.
Route::get('health', [HealthController::class, 'check']);

Route::middleware(['throttle:public'])->group(function () {
    // Still public: throttle is not authentication.
    Route::post('auth/sign-in', [AuthController::class, 'signIn']);
});

// AUTHENTICATED: everything inside inherits auth:api.
Route::middleware(['auth:api'])->group(function () {

    Route::prefix('orders')->group(function () {
        // Authenticated, and the controller authorizes explicitly.
        Route::get('/{orderId}', [OrderController::class, 'show']);

        // Authenticated, authorized by policy middleware.
        Route::delete('/{orderId}', [OrderController::class, 'destroy'])
            ->middleware('can:delete,order');

        // Authenticated, but no authorization control that we can see.
        Route::get('/', [OrderController::class, 'index']);
    });

    // AMBIGUOUS: the path is computed, so the operation cannot be identified.
    Route::get(config('custom.dynamic_route'), [OrderController::class, 'dynamic']);

    // AMBIGUOUS: the handler is not among the inspected files.
    Route::get('reports/{reportId}', [MissingController::class, 'show']);
});
