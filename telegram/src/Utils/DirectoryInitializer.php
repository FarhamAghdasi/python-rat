<?php
namespace Utils;

class DirectoryInitializer
{
    public static function init(array $dirs)
    {
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }
}