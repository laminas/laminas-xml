<?php

/**
 * @see       https://github.com/laminas/laminas-xml for the canonical source repository
 * @copyright https://github.com/laminas/laminas-xml/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-xml/blob/master/LICENSE.md New BSD License
 */
namespace LaminasTest\Xml;

use DOMDocument;
use Laminas\Xml\Exception;
use Laminas\Xml\Security as XmlSecurity;
use SimpleXMLElement;

class SecurityTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException Laminas\Xml\Exception\RuntimeException
     */
    public function testScanForXEE()
    {
        $xml = <<<XML
<?xml version="1.0"?>
<!DOCTYPE results [<!ENTITY harmless "completely harmless">]>
<results>
    <result>This result is &harmless;</result>
</results>
XML;

        $this->setExpectedException('Laminas\Xml\Exception\RuntimeException');
        $result = XmlSecurity::scan($xml);
    }

    public function testScanForXXE()
    {
        $file = tempnam(sys_get_temp_dir(), 'laminas-xml_Security');
        file_put_contents($file, 'This is a remote content!');
        $xml = <<<XML
<?xml version="1.0"?>
<!DOCTYPE root
[
<!ENTITY foo SYSTEM "file://$file">
]>
<results>
    <result>&foo;</result>
</results>
XML;

        try {
            $result = XmlSecurity::scan($xml);
        } catch (Exception\RuntimeException $e) {
            unlink($file);
            return;
        }
        $this->fail('An expected exception has not been raised.');
    }

    public function testScanSimpleXmlResult()
    {
        $result = XmlSecurity::scan($this->_getXml());
        $this->assertTrue($result instanceof SimpleXMLElement);
        $this->assertEquals($result->result, 'test');
    }

    public function testScanDom()
    {
        $dom = new DOMDocument('1.0');
        $result = XmlSecurity::scan($this->_getXml(), $dom);
        $this->assertTrue($result instanceof DOMDocument);
        $node = $result->getElementsByTagName('result')->item(0);
        $this->assertEquals($node->nodeValue, 'test');
    }

    public function testScanInvalidXml()
    {
        $xml = <<<XML
<foo>test</bar>
XML;

        $result = XmlSecurity::scan($xml);
        $this->assertFalse($result);
    }

    public function testScanInvalidXmlDom()
    {
        $xml = <<<XML
<foo>test</bar>
XML;

        $dom = new DOMDocument('1.0');
        $result = XmlSecurity::scan($xml, $dom);
        $this->assertFalse($result);
    }

    public function testScanFile()
    {
        $file = tempnam(sys_get_temp_dir(), 'laminas-xml_Security');
        file_put_contents($file, $this->_getXml());

        $result = XmlSecurity::scanFile($file);
        $this->assertTrue($result instanceof SimpleXMLElement);
        $this->assertEquals($result->result, 'test');
        unlink($file);
    }

    public function testScanXmlWithDTD()
    {
        $xml = <<<XML
<?xml version="1.0"?>
<!DOCTYPE results [
<!ELEMENT results (result+)>
<!ELEMENT result (#PCDATA)>
]>
<results>
    <result>test</result>
</results>
XML;

        $dom = new DOMDocument('1.0');
        $result = XmlSecurity::scan($xml, $dom);
        $this->assertTrue($result instanceof DOMDocument);
        $this->assertTrue($result->validate());
    }

    protected function _getXml()
    {
        return <<<XML
<?xml version="1.0"?>
<results>
    <result>test</result>
</results>
XML;

    }    
    
}
