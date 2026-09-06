<?php
namespace App\Http\Controllers;

class OrderController extends Controller
{
    public function show(int $orderId)
    {
        Gate::authorize('view-order');
        return Order::findOrFail($orderId);
    }

    public function index()
    {
        // Deliberately no authorization call.
        return Order::all();
    }

    public function destroy(int $orderId)
    {
        return Order::destroy($orderId);
    }
}
