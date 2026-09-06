<?php
namespace App\Http\Controllers;
class HealthController extends Controller
{
    public function check() { return ['ok' => true]; }
}
