#include <fstream>
#include <cppunit/TestResult.h>
#include <cppunit/XmlOutputter.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/extensions/TestFactoryRegistry.h>

int main( int argc, char **argv)
{
	CppUnit::TextUi::TestRunner runner;
	CppUnit::TestResultCollector  collector;
	CppUnit::TestResult result;
	result.addListener(&collector);

	CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry();
	runner.addTest(registry.makeTest());

	// Run the tests.
	runner.run(result);


	// writing result on a XML file
	std::ofstream xmlFileOut("testresults.xml");
	CppUnit::XmlOutputter xmlOut(&collector, xmlFileOut);
	xmlOut.write();
	
	// Return error code 1 if the one of test failed.
	return 0;
}
