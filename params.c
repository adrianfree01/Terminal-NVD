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
	char* output = malloc(2048);
	switch(input)
	{ 
		case 1: // CPE Name
            		strcat(output, "cpeName=cpe:2.3:");

            		char cpeNameInput[256]; // Allocate enough memory for inputs

            		printf("\nPart (Required) either a (application) o (operating system) h (hardware): ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
           		strcat(output, ":");

            		printf("\nVendor (Required): ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nProduct (Required): ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nVersion (Required): ");
            		scanf("%255s", cpeNameInput);
         		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nUpdate: ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nEdition: ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nLanguage: ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nSoftware Edition: ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nTarget Software: ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nTarget Hardware: ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);
            		strcat(output, ":");

            		printf("\nOther: ");
            		scanf("%255s", cpeNameInput);
            		strcat(output, cpeNameInput);        
            		break;
        	


		case 2: // CVE ID
			strcat(output, "cveId=");
			printf("\nCVE ID: ");
			char cveId[256];
			scanf("%255s", cveId);
			strcat(output, cveId);
			break;

		case 3: // CVE Tag
			strcat(output, "cveTag=");
			printf("\nCVE ID (disputed, unsupported-when-assigned, exclusively-hosted-service): ");
			char cveTag[256];
			scanf("%255s", cveTag);
			strcat(output, cveTag);
			break;	

		case 4: // CVSS v2 Metrics
			strcat(output, "cvssV2Metrics=AV:"
			printf("\nAccess Vector (L, A, N): ");
			char cvssMetrics[256];
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/AC:");
			printf("\nAccess Complexity (H, M, L): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);
	
			strcat(output, "/AU:");
			printf("\nAuthentication (M, S, N): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);


			strcat(output, "/C:");
			printf("\nConfidentiality Impact (N, P, C): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);


			strcat(output, "/I:");
			printf("\nIntegrity Impact (N, P, C): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);


			strcat(output, "/A:");
			printf("\nAvailability Impact (N, P, C): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			break;

		case 5: // CVSS v2 Severity
			strcat(output, "cvssV2Severity=");
			printf("\nCVSS V2 Severity (LOW, MEDIUM, HIGH): ");
			char cvssSeverity[256];
			scanf("%255s", cvssSeverity);
			strcat(output, cvssSeverity);
			break;

		case 6: // CVSS v3 Metrics
			strcat(output, "cvssV3Metrics=AV:"
			printf("\nAccess Vector (L, A, N, P): ");
			char cvssMetrics[256];
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/AC:");
			printf("\nAccess Complexity (H, L): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);
	
			strcat(output, "/PR:");
			printf("\nPrivileges Required (N, L, H): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/UI:");
			printf("\nUser Interaction (N, R): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/S:");
			printf("\nScope (U, C): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/C:");
			printf("\nConfidentiality Impact (N, P, C): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/I:");
			printf("\nIntegrity Impact (N, P, C): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/A:");
			printf("\nAvailability Impact (N, P, C): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			break;
		case 7: // CVSS v3 Severity
			strcat(output, "cvssV3Severity=");
			printf("\nCVSS V3 Severity (LOW, MEDIUM, HIGH, CRITICAL): ");
			char cvssSeverity[256];
			scanf("%255s", cvssSeverity);
			strcat(output, cvssSeverity);
			break;

		case 8: // CVSS v4 Metrics
			strcat(output, "cvssV4Metrics=AV:"
			printf("\nAccess Vector (L, A, N, P): ");
			char cvssMetrics[256];
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/AC:");
			printf("\nAccess Complexity (H, L): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);
	
			strcat(output, "/AT:");
			printf("\nAttack Requirements (N, P): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/PR:");
			printf("\nPrivileges Required (N, L, H): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			strcat(output, "/UI:");
			printf("\nUser Interaction (N, R): ");
			scanf("%255s", cvssMetrics);
			strcat(output, cvssMetrics);

			//STOPPED HERE
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
