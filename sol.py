import requests

TIMEOUT_MAX_VAL = 1 # Protect hash key
MD5_LENGTH = 32
SHA1_LENGTH = 32
SHA256_LENGTH = 32


def extract_data(data):
    file_information = {'MD5': data['md5'], 'SHA-1': data['sha1'], 'SHA-256': data['sha256']}
    last_analysis_status = build_last_analysis_status_dict(data['last_analysis_stats'])
    last_analysis_results = build_last_analysis_results_list(data['last_analysis_results'])
    return file_information, last_analysis_status, last_analysis_results

# Gets the json formatted response from requests
# Returns the last analysis status table as dictionary variable
def build_last_analysis_status_dict(stats):
    count_total_analysis, count_malicious_analysis = 0, 0
    for analysis in stats['scans']:
        if stats['scans'][analysis]['detected'] == True:
            count_malicious_analysis = count_malicious_analysis + 1
        count_total_analysis = count_total_analysis + 1
    last_analysis_status_dict = {}
    last_analysis_status_dict['Total Scans'] = count_total_analysis # Using __len__ is inefficient in this case
    last_analysis_status_dict['Malicious Scans'] = count_malicious_analysis
    return last_analysis_status_dict

# Gets the json formatted response from requests
# Returns the last analysis results table as set of dictionaries variable
def build_last_analysis_results_list(results):
    last_analysis_results_list = []
    for analysis in results['scans']:
        last_analysis_results_list.append([analysis, results['scans'][analysis]['result']])
    return last_analysis_results_list

# Returns markdown table format as requested in home exercise
def get_markdown_table_format(file_information, last_analysis_status, last_analysis_results):
    '''
    Markdown table format is: 

    |Left-aligned|Right-aligned|
    |-|-|
    |Pressure|P|
    |Temperature|T|
    |Velocity|v|

    '  \n' stands for newline
    '''
    file_information_markdown_table_header = create_formatted_markdown_string_header(file_information.keys())
    file_information_markdown_table_values = create_formatted_markdown_string_line(file_information.values())
    markdown_table_1 = '  \n'.join([file_information_markdown_table_header, file_information_markdown_table_values])
    last_analysis_status_markdown_table_header = create_formatted_markdown_string_header(last_analysis_status.keys())
    last_analysis_status_markdown_table_values = create_formatted_markdown_string_line(last_analysis_status.values())
    markdown_table_2 = '  \n'.join([last_analysis_status_markdown_table_header, last_analysis_status_markdown_table_values])
    last_analysis_results_markdown_table_header = create_formatted_markdown_string_header(['Scan Origin (name)', 'Scan Result (category)'])
    last_analysis_results_markdown_table_values = create_formatted_markdown_string_list(last_analysis_results)
    markdown_table_3 = '  \n'.join([last_analysis_results_markdown_table_header, last_analysis_results_markdown_table_values])
    titles = ['# File information', markdown_table_1, '  \n# Last Analysis Status', markdown_table_2, '  \n# Last Analysis Results', markdown_table_3]
    return '  \n'.join(titles)
    
def create_formatted_markdown_string_header(some_dict):
    formatted_string = ''
    for key in some_dict:
        formatted_string = formatted_string + '|' + key
    formatted_string = formatted_string + '|'
    return '  \n'.join([formatted_string, ('|-' * len(some_dict)) + '|'])

def create_formatted_markdown_string_line(some_dict):
    formatted_string = ''
    for value in some_dict:
        if isinstance(value, str) == False:
            value = str(value)
        formatted_string = formatted_string + '|' + value
    formatted_string = formatted_string + '|'
    return formatted_string

def create_formatted_markdown_string_list(some_dict):
    formatted_string = ''
    for value in some_dict:
        formatted_string = '  \n'.join([formatted_string, create_formatted_markdown_string_line(value)])
    return formatted_string[4:]

def from_file_hash_to_markdown_table(api_key, hash):
    try:
        if (api_key == None) or (len(hash) not in [MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH]):
            raise ValueError
    except ValueError:
        print('Wrong input. You should enter a valid file hash and API key given from VirusTotal.', sep='\n')
    else:
        headers = {'x-apikey' : api_key}
        url = 'https://www.virustotal.com/api/v3/files/{id}'.format(id=hash)
        try:
            response = requests.get(url, headers=headers, timeout=TIMEOUT_MAX_VAL)
            response_json = response.json()
            if response.status_code >= 400:
                raise(requests.HTTPError())
        except requests.HTTPError:
            print(response_json['error']['message'], sep='\n')
        else:
            file_information, last_analysis_status, last_analysis_results = extract_data(response_json['data']['attributes'])
            return get_markdown_table_format(file_information, last_analysis_status, last_analysis_results)
            

if __name__ == "__main__":
    my_api_key = 'uncensoreduncensoreduncensoreduncensoreduncensoredguybeckenstein'
    test_hash = '84c82835a5d21bbcf75a61706d8ab549'
    from_file_hash_to_markdown_table(my_api_key, test_hash)