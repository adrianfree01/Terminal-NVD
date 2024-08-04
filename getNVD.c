#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

/*
 * Intro to National Vulnerability Database (NVD) Project
 * Professor: Dr. Saqib Hakak
 * Student: Adrian Freeman (Student ID: 3661616)
 */

#define NVD_API_KEY "33de1ce2-aadf-425b-921b-3906095af181"
#define NVD_URL "https://services.nvd.nist.gov/rest/json/cves/2.0"
struct memoryStruct 
{
	char *memory;
	size_t size;
};

static size_t writeMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) 
{
	size_t realSize = size * nmemb;
	struct memoryStruct *mem = (struct memoryStruct *)userp;

	char *ptr = realloc(mem->memory, mem->size + realSize + 1);
	if (ptr == NULL) 
	{
		printf("Not enough memory\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realSize);
	mem->size += realSize;
	mem->memory[mem->size] = 0;

	return realSize;
}

char* makeRequest(const char* url) 
{
	CURL *curlHandle;
	CURLcode res;

	struct memoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;

	curl_global_init(CURL_GLOBAL_ALL);
	curlHandle = curl_easy_init();

	curl_easy_setopt(curlHandle, CURLOPT_URL, url);
	curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeMemoryCallback);
	curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, (void *)&chunk);

	struct curl_slist *headers = NULL;
	char header[256];
	snprintf(header, sizeof(header), "apiKey: %s", NVD_API_KEY);
	headers = curl_slist_append(headers, header);
	curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, headers);

	res = curl_easy_perform(curlHandle);
	if (res != CURLE_OK) 
	{
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		return NULL;
	}

	curl_easy_cleanup(curlHandle);
	curl_global_cleanup();
	return chunk.memory;
}

void parseJson(const char* jsonResponse) 
{
	cJSON *json = cJSON_Parse(jsonResponse);
	if (json == NULL) 
	{
		const char *errorPtr = cJSON_GetErrorPtr();
		if (errorPtr != NULL)
			fprintf(stderr, "Error before: %s\n", errorPtr);
		return;
	}

	char *formattedJson = cJSON_Print(json);
	printf("%s\n", formattedJson);
	free(formattedJson);
	cJSON_Delete(json);
}

int main(void)
{
	const char* url = NVD_URL;
	char* response = makeRequest(url);

	if (response) 
	{
		parseJson(response);
		free(response);
	}
	return 0;
}

