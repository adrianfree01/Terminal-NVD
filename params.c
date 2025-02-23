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
	char newInput[256];
	switch(input)
	{ 
		case 1: // CPE Name
            		strcat(output, "cpeName=cpe:2.3:");
            		printf("\nPart (Required) either a (application) o (operating system) h (hardware): ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
           		strcat(output, ":");

            		printf("\nVendor (Required): ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nProduct (Required): ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nVersion (Required): ");
            		scanf("%255s", newInput);
         		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nUpdate: ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nEdition: ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nLanguage: ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nSoftware Edition: ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nTarget Software: ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nTarget Hardware: ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);
            		strcat(output, ":");

            		printf("\nOther: ");
            		scanf("%255s", newInput);
            		strcat(output, newInput);        
            		break;
        	


		case 2: // CVE ID
			strcat(output, "cveId=");
			printf("\nCVE ID: ");
			scanf("%255s", newInput);
			strcat(output, newInput);
			break;

		case 3: // CVE Tag
			strcat(output, "cveTag=");
			printf("\nCVE ID (disputed, unsupported-when-assigned, exclusively-hosted-service): ");
			scanf("%255s", newInput);
			strcat(output, newInput);
			break;	

		case 4: // CVSS v2 Metrics
			strcat(output, "cvssV2Metrics=AV:");
			printf("\nAccess Vector (L, A, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/AC:");
			printf("\nAccess Complexity (H, M, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);
	
			strcat(output, "/Au:");
			printf("\nAuthentication (M, S, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			strcat(output, "/C:");
			printf("\nConfidentiality Impact (N, P, C): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			strcat(output, "/I:");
			printf("\nIntegrity Impact (N, P, C): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			strcat(output, "/A:");
			printf("\nAvailability Impact (N, P, C): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			break;

		case 5: // CVSS v2 Severity
		
			strcat(output, "cvssV2Severity=");
			printf("\nCVSS V2 Severity (LOW, MEDIUM, HIGH): ");
			scanf("%255s", newInput);
			strcat(output, newInput);
			break;

		case 6: // CVSS v3 Metrics
		
			strcat(output, "cvssV3Metrics=AV: ");
			printf("\nAccess Vector (L, A, N, P): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/AC:");
			printf("\nAccess Complexity (H, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);
	
			strcat(output, "/PR:");
			printf("\nPrivileges Required (N, L, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/UI:");
			printf("\nUser Interaction (N, R): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/S:");
			printf("\nScope (U, C): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/C:");
			printf("\nConfidentiality Impact (N, L, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/I:");
			printf("\nIntegrity Impact (N, L, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/A:");
			printf("\nAvailability Impact (N, L, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nTemporal Score Metrics");

			strcat(output, "/E:");
			printf("\nExploit Code Maturity (X, U, P, F, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/RL:");
			printf("\nRemediation Level (X, O, T, W, U): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/RC:");
			printf("\nReport Confidence (X, U, R, C): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nExploitabilty Metrics");

			strcat(output, "/MAV: ");
			printf("\nAccess Vector (X, L, A, N, P): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MAC:");
			printf("\nAccess Complexity (X, H, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MPR:");
			printf("\nPrivileges Required (X, N, L, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MUI:");
			printf("\nUser Interaction (X, N, R): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MS:");
			printf("\nScope (X, U, C): ");
			scanf("%255s", newInput);
			strcat(output, newInput);



			printf("\nImpact Metrics");

			strcat(output, "/MC:");
			printf("\nConfidentiality (X, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MI:");
			printf("\nIntegrity (X, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MA");
			printf("\nAvailability (X, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nImpact Subscore Modifiers");

			strcat(output, "/CR");
			printf("\nConfidentiality Requirements (X, H, M, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/IR");
			printf("\nIntegrity Requirements (X, H, M, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/AR");
			printf("\nAvailability Requirements (X, H, M, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			break;

		case 7: // CVSS v3 Severity
			strcat(output, "cvssV3Severity=");
			printf("\nCVSS V3 Severity (LOW, MEDIUM, HIGH, CRITICAL): ");
			scanf("%255s", newInput);
			strcat(output, newInput);
			break;

		case 8: // CVSS v4 Metrics
			strcat(output, "cvssV4Metrics=AV: ");
			printf("\nAccess Vector (L, A, N, P): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/AC:");
			printf("\nAccess Complexity (H, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);
	
			strcat(output, "/AT:");
			printf("\nAttack Requirements (N, P): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/PR:");
			printf("\nPrivileges Required (N, L, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/UI:");
			printf("\nUser Interaction (N, P, A): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nVulnerable Systems Impact Metrics: ");
		
			strcat(output, "/VC:");
			printf("\nConfidentiality (H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/VI:");
			printf("\nIntegrity (H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/VA");
			printf("\nAvailability (H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nSubsequent Systems Impact Metrics");

			strcat(output, "/SC:");
			printf("\nConfidentiality (H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/SI:");
			printf("\nIntegrity (H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/SA");
			printf("\nAvailability (H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nSupplemental Metrics");

			strcat(output, "/S:");
			printf("\nSafety (X, N, P): ");
			scanf("255s", newInput);
			strcat(output, newInput);

			strcat(output, "/AU:");
			printf("\nAutomatable (X, N, Y): ");
			scanf("255s", newInput);
			strcat(output, newInput);

			strcat(output, "/R:");
			printf("\nRecovery (X, A, U, I): ");
			scanf("255s", newInput);
			strcat(output, newInput);

			strcat(output, "/V:");
			printf("\nValue Density (X, D, C): ");
			scanf("255s", newInput);
			strcat(output, newInput);

			strcat(output, "/RE:");
			printf("\nVulnerability Response Effort (X, L, M, H): ");
			scanf("255s", newInput);
			strcat(output, newInput);

			strcat(output, "/U:");
			printf("\nProvider Urgency (X, Clear, Green, Amber, Red): ");
			scanf("255s", newInput);
			strcat(output, newInput);


			printf("\nEnvironmental (Modified Base Metrics): ");

			strcat(output, "/MAV: ");
			printf("\nAccess Vector (X, L, A, N, P): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MAC:");
			printf("\nAccess Complexity (X, H, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);
	
			strcat(output, "/MAT:");
			printf("\nAttack Requirements (X, N, P): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MPR:");
			printf("\nPrivileges Required (X, N, L, H): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MUI:");
			printf("\nUser Interaction (X, N, P, A): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nVulnerable Systems Impact Metrics: ");
		
			strcat(output, "/MVC:");
			printf("\nConfidentiality (X, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MVI:");
			printf("\nIntegrity (X, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MVA");
			printf("\nAvailability (X, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nSubsequent Systems Impact Metrics");

			strcat(output, "/MSC:");
			printf("\nConfidentiality (X, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MSI:");
			printf("\nIntegrity (X, S, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/MSA");
			printf("\nAvailability (X, S, H, L, N): ");
			scanf("%255s", newInput);
			strcat(output, newInput);


			printf("\nEnvironmental (Security Requirements)");

			strcat(output, "/CR");
			printf("\nConfidentiality Requirements (X, H, M, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/IR");
			printf("\nIntegrity Requirements (X, H, M, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			strcat(output, "/AR");
			printf("\nAvailability Requirements (X, H, M, L): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			
			printf("\nThreat Metrics");

			strcat(output, "/E");
			printf("\nExploit Maturity (X, A, P, U): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			break;

		case 9 : // CVSS v4 Severity
			strcat(output, "cvssV4Severity=");
			printf("\nCVSS V4 Severity (LOW, MEDIUM, HIGH, CRITICAL): ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			break;	

		case 10: // CWE ID
			strcat(output, "cewId=");
			printf("\nCWE ID: ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			break;

		case 11: // Contains Technical Alert from US-CERT
			strcat(output, "hasCertAlerts");
		
			break;

		case 12: // Contains Vulnerability Note from CERT/C
			strcat(output, "hasCertNotes");
			break;
		case 13: // Appears in Known Exploited Vulnerabilities (KEV) Catalog
			strcat(output, "hasKev");
			break;

		case 14: // Contains info from MITRE's Open Vulnerability and Assessment Language (OVAL)
			strcat(output, "hasOval");
			break;

		case 15: // Is Vulnerable
			strcat(output, "isVulnerable");
			break;	

		case 16: // Search by Keyword Exact Match
			strcat(output, "keywordSearch="
			printf("\nEnter Keyword(s) to search for: ");
			scanf("%255s", newInput);
			strcat(output, newInput);
			strcat(output, "&keywordExactMatch");

			break;

		case 17: // Search by Keyword
			strcat(output, "keywordSearch="
			printf("\nEnter Keyword(s) to search for: ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			break;

		case 18: // Last Modified Date Range

			break;

		case 19: // Not Rejected
			strcat(output, "noRejected");
			break;

		case 20: // Published Date Range

			break;

		case 21: // Number of Results
			strcat(output, "resultsPerPage=");
			printf("\nEnter number of results per page: ");
			scanf("%255s", newInput);
			strcat(output, newInput);

			break;	

		case 22: // Start Index
			strcat(output, "startIndex=");
			printf("\nEnter start index: ");
			scanf("%255s", newInput);
			strcat(output, newInput);
			break;

		case 23: // Source Identifier
			strcat(output, "sourceIdentifier=");
			printf("\nEnter source identifier");
			scanf("%255s", newInput);
			strcat(output, newInput);

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
