# coding: utf-8
import argparse
import csv
import os
import sys
from subprocess import Popen, PIPE


def sed(pattern, filepath):
    """
    sed -n pattern mode wrapper
    :param pattern: sed -n 'pattern' file, pattern string
    :param filepath: some_file path
    :return: sed command result
    """
    p = Popen(['sed', "-n", f'{pattern}', filepath],
              shell=False, stderr=PIPE, stdout=PIPE)
    res, err = p.communicate()

    if err:
        assert False, f"{filepath} ???"
    return res.decode()


def format_rate(rate):
    return format(rate*100, '.2f')


def parser_result(filepath):
    result_not_found_array = sed(
        r"s/^Not found count: \(.*\)/\1/gp", filepath).split('\n')
    tp = sed(r"s/^Success count: \(.*\)/\1/gp", filepath).split('\n')[0]
    ground_truth = sed(
        r"s/^OBJDump file Ins count: \(.*\)/\1/gp", filepath).split('\n')[0]

    try:
        tp = int(tp)
        fn = int(result_not_found_array[0])
        fp = int(result_not_found_array[1])
    except ValueError:
        return "?", "?", "?", "?", "?", "?", "?"

    fpr = (fp)/(tp+fp)
    fnr = (fn)/(tp+fn)
    pr = 1-fpr
    rc = 1-fnr
    return tp, fp, fn, format_rate(fpr), format_rate(fnr), format_rate(pr), format_rate(rc)


def main(argv):
    parser = argparse.ArgumentParser(
        description='Generate GRIN result from .result')

    parser.add_argument('result_dir', metavar='result_dir', type=str,
                        help='Result Dir')
    parser.add_argument('-o', metavar='output', type=str,
                        help='Result output Path')

    args = parser.parse_args(argv)

    total_result = dict()

    for (dir_path, dir_names, filename_list) in os.walk(args.result_dir):
        for filename in filename_list:
            if os.path.splitext(filename)[-1] == '.result':
                total_result[filename.rstrip('result')] = parser_result(
                    os.path.join(dir_path, filename))

    if args.o is not None:
        csv_result_file = args.o
    else:
        csv_result_file = os.path.join(args.result_dir, 'result.csv')

    csv_result = open(csv_result_file, 'w', encoding='utf-8', newline='')

    csv_result_writer = csv.writer(csv_result)

    csv_result_writer.writerow(['Benchmark', 'True Positives', 'False Positives',
                               'False Negatives', 'FP Rate (%)', 'FN Rate (%)', "Precision (%)", "Recall (%)"])
    # generate csv format result
    for name, result in total_result.items():
        temp_result = [name.rstrip('.')]
        temp_result.extend(result)
        csv_result_writer.writerow(temp_result)
    csv_result.close()

    # generate ascii format table result

    table_line_str = "+---------------+------------------+------------------+------------------+---------------+---------------+---------------+---------------+\n"

    talbe_format_str = "|{:^15}|{:^18}|{:^18}|{:^18}|{:^15}|{:^15}|{:^15}|{:^15}|\n"

    table_str = table_line_str + talbe_format_str.format(
        "Benchmark", "True Positives", "False Positives", "False Negatives", "FP Rate (%)", "FN Rate (%)", "Precision (%)", "Recall (%)") + table_line_str

    for name, result in total_result.items():
        table_str += talbe_format_str.format(name.rstrip('.'), *result)

    table_str += table_line_str

    ascii_table_file = csv_result_file+".ascii_table.txt"

    with open(ascii_table_file, 'w', encoding='utf-8') as f:
        f.write(table_str)
        f.close()

    print(f'ASCII table format result in: {ascii_table_file}')

    print(f"Result csv file in: {csv_result_file}")

    pass


if __name__ == '__main__':
    main(sys.argv[1:])
