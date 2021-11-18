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
    p = Popen(['sed', "-n", f'{pattern}', filepath], shell=False, stderr=PIPE, stdout=PIPE)
    res, err = p.communicate()

    if err:
        assert False, f"{filepath} ???"
    return res.decode()


def parser_result(filepath):
    result_not_found_array = sed(r"s/^Not found count: \(.*\)/\1/gp", filepath).split('\n')
    tp = sed(r"s/^Success count: \(.*\)/\1/gp", filepath).split('\n')[0]
    ground_truth = sed(r"s/^OBJDump file Ins count: \(.*\)/\1/gp", filepath).split('\n')[0]

    fn = int(result_not_found_array[0])
    fp = int(result_not_found_array[1])

    return ground_truth, tp, fp, fn


def main(argv):
    parser = argparse.ArgumentParser(description='Generate GRIN result from .result')

    parser.add_argument('result_dir', metavar='result_dir', type=str,
                        help='Result Dir')
    parser.add_argument('-o', metavar='output', type=str
                        , help='Result output Path')

    args = parser.parse_args(argv)

    total_result = dict()

    for (dir_path, dir_names, filename_list) in os.walk(args.result_dir):
        for filename in filename_list:
            if os.path.splitext(filename)[-1] == '.result':
                total_result[filename.rstrip('result')] = parser_result(os.path.join(dir_path, filename))

    if args.o is not None:
        csv_result_file = args.o
    else:
        csv_result_file = os.path.join(args.result_dir, 'result.csv')

    csv_result = open(csv_result_file, 'w', encoding='utf-8', newline='')

    csv_result_writer = csv.writer(csv_result)

    csv_result_writer.writerow(['name', 'gt', 'tp', 'fp', 'fn'])
    # generate csv format result
    for name, result in total_result.items():
        temp_result = [name.rstrip('.')]
        temp_result.extend(result)
        csv_result_writer.writerow(temp_result)

    print(f"Result csv file in: {csv_result_file}")

    pass


if __name__ == '__main__':
    main(sys.argv[1:])
