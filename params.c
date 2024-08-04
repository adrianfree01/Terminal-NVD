#include "params.h"
/*
	1: CPE Name\n
	2: CVE ID\n
	3: CVE Tag\n
	4: CVSS v2 Metrics\n
	5: CVSS v2 Severity\n
	6: CVSS v3 Metrics\n
	7: CVSS v3 Security\n
	8: CVSS v4 Metrics\n
	9: CVSS v4 Severity\n
	10: CWE ID\n
	11: Contains Technical Alert from US-CERT\n
	12: Contains Vulnerability Note from CERT/C\n
	13: Appears in Known Exploited Vulnerabilities (KEV) Catalog\n
	14: Contains info from MITRE's Open Vulnerability and Assessment Language (OVAL)\n
	15: Is Vulnerable\n
	16: Search by Keyword Exact Match\n
	17: Search by Keyword\n
	18: Last Modified Date Range\n
	19: Not Rejected\n
	20: Published Date Range\n
	21: Number of Results\n
	22: Start Index\n
	23: Source Identifier\n
	24: CPE Version Start\n
	25: CPE Version End\n
	26: CPE Match\n");
 */

char* generateRequest(int input) 
{
	char* output;
	switch(input) 
	{
		case 1: // CPE Name
			output = "cpeName=cpe:2.3:";
			printf("\nPart: ");
			char* cpeNameInput;
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nVendor: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nProduct: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nVersion: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nUpdate: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nEdition: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nLanguage: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nSoftware Edition: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nTarget Software: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nTarget Hardware: ");
			scanf("%s", &cpeNameInput);
			strcat(output, strcat(cpeNameInput, ":"));

			printf("\nOther: ");
			scanf("%s", &cpeNameInput);
			strcat(output, cpeNameInput);		
			break;

		case 2: // CVE ID

			break;

		case 3: // CVE Tag

			break;	

		case 4: // CVSS v2 Metrics

			break;

		case 5: // CVSS v2 Severity

			break;

		case 6: // CVSS v3 Metrics

			break;
		case 7: // CVSS v3 Severity

			break;

		case 8: // CVSS v4 Metrics

			break;

		case 9 : // CVSS v4 Severity

			break;	

		case 10: // CWE ID

			break;

		case 11: // Contains Technical Alert from US-CERT

			break;

		case 12: // Contains Vulnerability Note from CERT/C

			break;
		case 13: // Appears in Known Exploited Vulnerabilities (KEV) Catalog

			break;

		case 14: // Contains info from MITRE's Open Vulnerability and Assessment Language (OVAL)

			break;

		case 15: // Is Vulnerable

			break;	

		case 16: // Search by Keyword Exact Match

			break;

		case 17: // Search by Keyword

			break;

		case 18: // Last Modified Date Range

			break;

		case 19: // Not Rejected

			break;

		case 20: // Published Date Range

			break;

		case 21: // Number of Results

			break;	

		case 22: // Start Index

			break;

		case 23: // Source Identifier

			break;

		case 24: // CPE Version Start

			break;

		case 25: // CPE Version End

			break;

		case 26: // CPE Match

			break;
	}

	return output;
}
