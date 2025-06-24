<?php
class Autoloader
{
    public static function register()
    {
        spl_autoload_register(function ($class) {
            $baseDir = __DIR__ . '/';
            $relativePath = str_replace('\\', '/', $class) . '.php';
            $file = $baseDir . $relativePath;
            if (file_exists($file)) {
                require_once $file;
            }
        });
    }
}
