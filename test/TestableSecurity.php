<?php

namespace LaminasTest\Xml;

use Laminas\Xml\Security;

class TestableSecurity extends Security
{
    public static function heuristicScan($xml): void
    {
        parent::heuristicScan($xml);
    }
}
