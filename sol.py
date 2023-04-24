import requests
import datetime

TIMEOUT_MAX_VAL = 1  # Protect hash key
MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64
NEWLINE = '  \n'
SEP = '|'


def from_file_hash_to_markdown_table(api_key: str, hash_key: str) -> str:
    try:
        if (api_key is None) or (len(hash_key) not in [MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH]):
            raise ValueError
    except ValueError:
        print('Wrong input. You should enter a valid file hash and API key given from VirusTotal.')
    else:
        url: str = f'https://www.virustotal.com/api/v3/files/{hash_key}'
        headers: dict = {'x-apikey': api_key}
        response_json: dict = dict()
        try:
            response: requests.models.Response = requests.get(url=url, headers=headers, timeout=TIMEOUT_MAX_VAL)
            response_json = response.json()
            if response.status_code >= 400:
                raise requests.HTTPError()
        except requests.HTTPError:
            print(response_json['error']['message'])
        else:
            res: tuple = extract_latest_data(
                response_json['data']['attributes']
            )
            hashing_algorithms: dict = res[0]
            latest_analysis_status: dict = res[1]
            latest_analysis_results: list = res[2]
            return get_latest_markdown_formatted_table(
                hashing_algorithms,
                latest_analysis_status,
                latest_analysis_results
            )


def extract_latest_data(data: dict) -> (dict, dict, list):
    file_information: dict = {'MD5': data['md5'], 'SHA-1': data['sha1'], 'SHA-256': data['sha256']}
    analysis_status: dict = build_last_analysis_status_dict(data['last_analysis_stats'])
    analysis_results: list = build_last_analysis_results_list(data['last_analysis_results'])
    return file_information, analysis_status, analysis_results


# Gets the json formatted response from requests
# Returns the last analysis status table as dictionary variable
def build_last_analysis_status_dict(stats: dict) -> dict:
    count_total_analysis_scans: int = 0
    for analysis in stats:
        count_total_analysis_scans: int = count_total_analysis_scans + stats[analysis]
    last_analysis_status_dict: dict = {'Total Scans': count_total_analysis_scans, 'Malicious Scans': stats['malicious']}
    return last_analysis_status_dict


# Gets the json formatted response from requests
# Returns the last analysis results table as set of dictionaries variable
def build_last_analysis_results_list(results: dict) -> list:
    last_analysis_results_list: list = []
    for analysis in results:
        if results[analysis]['result'] is not None:
            latest_engine_update_date: tuple = (
                results[analysis]['engine_update'][-2:],
                results[analysis]['engine_update'][4:-2],
                results[analysis]['engine_update'][:4]
            )
            year: int = int(latest_engine_update_date[2])
            month: int = int(latest_engine_update_date[1])
            day: int = int(latest_engine_update_date[0])
            engine_update_date = datetime.date(year, month, day)

            today: datetime.date = datetime.date.today()
            last_analysis_results_list.append([
                analysis,
                results[analysis]['result'],
                (today - engine_update_date).days]
            )
    return last_analysis_results_list


# Returns Markdown table format as requested in home exercise
def get_latest_markdown_formatted_table(hashing_algorithms: dict, analysis_status: dict, analysis_results: list) -> str:
    """
    Markdown table format is:

    |Left-aligned|Right-aligned|
    |-|-|
    |Pressure|P|
    |Temperature|T|
    |Velocity|v|

    '  \n' stands for newline
    """

    file_information_markdown_table_header: str = get_markdown_formatted_header(hashing_algorithms.keys(), SEP, NEWLINE)
    file_information_markdown_table_values: str = create_markdown_formatted_content(hashing_algorithms.values(), SEP)
    latest_analysis_status_markdown_table_header: str = get_markdown_formatted_header(
        analysis_status.keys(),
        SEP,
        NEWLINE
    )
    latest_analysis_status_markdown_table_values: str = create_markdown_formatted_content(analysis_status.values(), SEP)
    latest_analysis_results_markdown_table_header: str = get_markdown_formatted_header(
        ['Scan Origin (name)', 'Scan Result (category)', 'Last Scan (days from now)'],
        SEP,
        NEWLINE
    )
    latest_analysis_results_markdown_table_values: str = create_markdown_formatted_list_content(
        analysis_results,
        SEP,
        NEWLINE
    )

    markdown_table_1: str = NEWLINE.join(
        [file_information_markdown_table_header, file_information_markdown_table_values]
    )
    markdown_table_2: str = NEWLINE.join(
        [latest_analysis_status_markdown_table_header, latest_analysis_status_markdown_table_values]
    )
    markdown_table_3: str = NEWLINE.join(
        [latest_analysis_results_markdown_table_header, latest_analysis_results_markdown_table_values]
    )

    titles: list = [
        '# File information', markdown_table_1,
        NEWLINE + '# Last Analysis Status', markdown_table_2,
        NEWLINE + '# Last Analysis Results', markdown_table_3
        ]
    return NEWLINE.join(titles)


def get_markdown_formatted_header(hashing_algorithms_names, SEP: str, NEWLINE: str) -> str:
    markdown_formatted_string: str = ''
    for key in hashing_algorithms_names:
        markdown_formatted_string = markdown_formatted_string + SEP + key
    markdown_formatted_string = markdown_formatted_string + SEP
    return NEWLINE.join([markdown_formatted_string, ((SEP + '-') * len(hashing_algorithms_names)) + SEP])


def create_markdown_formatted_content(hashing_algorithms_keys, SEP: str) -> str:
    markdown_formatted_string: str = ''
    for value in hashing_algorithms_keys:
        if isinstance(value, str) is False:
            value = str(value)
        markdown_formatted_string = markdown_formatted_string + SEP + value
    markdown_formatted_string = markdown_formatted_string + SEP
    return markdown_formatted_string


def create_markdown_formatted_list_content(antirivus_conclusion_lists: list, SEP: str, NEWLINE: str) -> str:
    markdown_formatted_string: str = ''
    for antirivus_conclusion_list in antirivus_conclusion_lists:
        markdown_formatted_string = NEWLINE.join([
            markdown_formatted_string,
            create_markdown_formatted_content(antirivus_conclusion_list, SEP)
        ])
    return markdown_formatted_string[4:]


if __name__ == "__main__":
    my_api_key: str = 'uncensoreduncensoreduncensoreduncensoreduncensoredguybeckenstein'
    test_hash: str = '84c82835a5d21bbcf75a61706d8ab549'
    print(from_file_hash_to_markdown_table(my_api_key, test_hash))
