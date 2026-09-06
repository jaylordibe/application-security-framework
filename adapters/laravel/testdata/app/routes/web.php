<?php
// A web route. It is not under the api prefix and must not be reported as one.
Route::get('/', function () { return view('welcome'); });
