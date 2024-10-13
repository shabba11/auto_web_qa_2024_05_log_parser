import os
import re
import json
from datetime import datetime

# Регулярное выражение для разбора строки лога
log_pattern = re.compile(
    r'(?P<ip>.*?) .*? .*? \[(?P<time>[^\]]+)\] \"(?P<request>.*? HTTP/.*)?\" (?P<status>.*?) (?P<size>.*?) \"('
    r'?P<referer>.*?)\" \"(?P<user_agent>.*?)\" (?P<duration>.*)'
)


def parse_log_line(line):
    match = log_pattern.match(line)
    if match:
        return {
            'ip': match.group('ip'),
            'time': datetime.strptime(match.group('time'), "%d/%b/%Y:%H:%M:%S %z"),
            'request': match.group('request'),
            'status': match.group('status'),
            'size': match.group('size'),
            'referer': match.group('referer'),
            'user_agent': match.group('user_agent'),
            'duration': match.group('duration')
        }
    return None


def analyze_log(file_path):
    request_count = 0
    method_count = {}
    ip_count = {}
    longest_requests = []

    with open(file_path, 'r') as f:
        for line in f:
            parsed_line = parse_log_line(line)
            if parsed_line:
                request_count += 1
                method = parsed_line['request'].split(' ')[0]
                method_count[method] = method_count[method] + 1 if method_count.get(method) else 1
                ip_count[parsed_line['ip']] = ip_count[parsed_line['ip']] + 1 if ip_count.get(parsed_line['ip']) else 1

                longest_requests.append((
                    method,
                    parsed_line['request'],
                    parsed_line['ip'],
                    parsed_line['duration'],
                    parsed_line['time']
                ))

    # Сортируем топы
    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:3]
    top_longest_requests = sorted(longest_requests, key=lambda x: x[3], reverse=True)[:3]

    stats = {
        'total_requests': request_count,
        'method_count': dict(method_count),
        'top_ips': top_ips,
        'top_longest_requests': [
            {
                'method': req[0],
                'url': req[1],
                'ip': req[2],
                'duration': req[3],
                'time': req[4].strftime("%Y-%m-%d %H:%M:%S %z")
            } for req in top_longest_requests
        ]
    }

    return stats


def save_stats_to_json(stats, output_file):
    with open(output_file, 'w') as f:
        json.dump(stats, f, indent=4)


def main(directory_or_file):
    if os.path.isfile(directory_or_file):
        files_to_process = [directory_or_file]
    else:
        files_to_process = [os.path.join(directory_or_file, f) for f in os.listdir(directory_or_file) if
                            f.endswith('.log')]

    for file_path in files_to_process:
        stats = analyze_log(file_path)

        # Выводим статистику в терминал
        print(f'Statistics for {file_path}:')
        print(json.dumps(stats, indent=4))

        # Сохраняем статистику в json файл
        output_file = f"{os.path.splitext(file_path)[0]}_stats.json"
        save_stats_to_json(stats, output_file)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Analyze access.log files.')
    parser.add_argument('directory_or_file', help='Path to directory containing log files or a specific log file.')
    args = parser.parse_args()

    main(args.directory_or_file)
