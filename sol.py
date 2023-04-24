import requests
import datetime
 
TIMEOUT_MAX_VAL = 1 # Protect hash key
MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64
 
def from_file_hash_to_markdown_table(api_key, hash) -> str:
    try:
        if (api_key == None) or (len(hash) not in [MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH]):
            raise ValueError
    except ValueError:
        print('Wrong input. You should enter a valid file hash and API key given from VirusTotal.', sep='\n')
    else:
        url = 'https://www.virustotal.com/api/v3/files/{id}'.format(id=hash)
        headers = {'x-apikey' : api_key}
        try:
            response = requests.get(url=url, headers=headers, timeout=TIMEOUT_MAX_VAL)
            response_json = response.json()
            if response.status_code >= 400:
                raise(requests.HTTPError())
        except requests.HTTPError:
            print(response_json['error']['message'], sep='\n')
        else:
            file_information, last_analysis_status, last_analysis_results = extract_data(response_json['data']['attributes'])
            return get_markdown_table(file_information, last_analysis_status, last_analysis_results)
 
def extract_data(data) -> dict, dict, list:
    file_information = {'MD5': data['md5'], 'SHA-1': data['sha1'], 'SHA-256': data['sha256']}
    last_analysis_status = build_last_analysis_status_dict(data['last_analysis_stats'])
    last_analysis_results = build_last_analysis_results_list(data['last_analysis_results'])
    return file_information, last_analysis_status, last_analysis_results
 
# Gets the json formatted response from requests
# Returns the last analysis status table as dictionary variable
def build_last_analysis_status_dict(stats) -> dict:
    count_total_analysis_scans = 0
    for analysis in stats:
        count_total_analysis_scans = count_total_analysis_scans + stats[analysis]
    last_analysis_status_dict = {}
    last_analysis_status_dict['Total Scans'] = count_total_analysis_scans # Using __len__ is inefficient in this case
    last_analysis_status_dict['Malicious Scans'] = stats['malicious']
    return last_analysis_status_dict
 
# Gets the json formatted response from requests
# Returns the last analysis results table as set of dictionaries variable
def build_last_analysis_results_list(results) -> list:
    last_analysis_results_list = []
    for analysis in results:
        if results[analysis]['result'] != None:
            str_eng_update = (results[analysis]['engine_update'][-2:], results[analysis]['engine_update'][4:-2], results[analysis]['engine_update'][:4])
            today = datetime.date.today()
            engine_update = datetime.date(int(str_eng_update[2]), int(str_eng_update[1]), int(str_eng_update[0]))
            last_analysis_results_list.append([analysis, results[analysis]['result'], (today - engine_update).days])
    return last_analysis_results_list
 
# Returns markdown table format as requested in home exercise
def get_markdown_table(file_information, last_analysis_status, last_analysis_results) -> str:
    '''
    Markdown table format is: 
 
    |Left-aligned|Right-aligned|
    |-|-|
    |Pressure|P|
    |Temperature|T|
    |Velocity|v|
 
    '  \n' stands for newline
    '''
    newline_token = '  \n'
    sep_token = '|'
 
    file_information_markdown_table_header = get_formatted_markdown_header(file_information.keys(), sep_token, newline_token)
    file_information_markdown_table_values = create_formatted_markdown_content(file_information.values(), sep_token)
    last_analysis_status_markdown_table_header = get_formatted_markdown_header(last_analysis_status.keys(), sep_token, newline_token)
    last_analysis_status_markdown_table_values = create_formatted_markdown_content(last_analysis_status.values(), sep_token)
    last_analysis_results_markdown_table_header = get_formatted_markdown_header(['Scan Origin (name)', 'Scan Result (category)', 'Last Scan (days from now)'], sep_token, newline_token)
    last_analysis_results_markdown_table_values = create_formatted_markdown_list_content(last_analysis_results, sep_token, newline_token)
 
    markdown_table_1 = newline_token.join([file_information_markdown_table_header, file_information_markdown_table_values])
    markdown_table_2 = newline_token.join([last_analysis_status_markdown_table_header, last_analysis_status_markdown_table_values])
    markdown_table_3 = newline_token.join([last_analysis_results_markdown_table_header, last_analysis_results_markdown_table_values])
 
    titles = ['# File information', markdown_table_1, 
              newline_token + '# Last Analysis Status', markdown_table_2, 
              newline_token + '# Last Analysis Results', markdown_table_3]
    return newline_token.join(titles)
 
def get_formatted_markdown_header(some_dict, sep_token, newline_token) -> str:
    formatted_string = ''
    for key in some_dict:
        formatted_string = formatted_string + sep_token + key
    formatted_string = formatted_string + sep_token
    return newline_token.join([formatted_string, ((sep_token + '-') * len(some_dict)) + sep_token])
 
def create_formatted_markdown_content(some_dict, sep_token) -> str:
    formatted_string = ''
    for value in some_dict:
        if isinstance(value, str) == False:
            value = str(value)
        formatted_string = formatted_string + sep_token + value
    formatted_string = formatted_string + sep_token
    return formatted_string
 
def create_formatted_markdown_list_content(some_dict, sep_token, newline_token) -> str:
    formatted_string = ''
    for value in some_dict:
        formatted_string = newline_token.join([formatted_string, create_formatted_markdown_content(value, sep_token)])
    return formatted_string[4:]
 
if __name__ == "__main__":
    my_api_key = 'uncensoreduncensoreduncensoreduncensoreduncensoredguybeckenstein'
    test_hash = '84c82835a5d21bbcf75a61706d8ab549'
    print(from_file_hash_to_markdown_table(my_api_key, test_hash))
