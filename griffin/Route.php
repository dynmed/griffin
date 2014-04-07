<?php
namespace Griffin;

class Route {
    public function GET() {}
    public function POST() {}
}

class Foo extends Route {
    public function GET() {
        echo "GET Foo!";
    }
}
?>
