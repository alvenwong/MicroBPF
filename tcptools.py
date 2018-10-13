#!/usr/bin/env python

from subprocess import Popen, PIPE

NAME_EQUAL  = 0
NAME_PREFIX = 1
NAME_SUFFIX = 2
NAME_NOT    = -1

def __check_name(name, postname):
    prefix = "__"
    suffix = ".isra."
    if postname == name:
        return NAME_EQUAL
    elif postname == prefix + name:
        return NAME_PREFIX
    elif postname.find(name+suffix) > -1:
        return NAME_SUFFIX
    return NAME_NOT


def check_filename(string):
    # the first character should be letter
    if not string[0].isalpha():
        return False
    for i in range(1, len(string)):
        char = string[i]
        if not char.isalpha() and not char.isdigit() and char != '-' and char != '_':
            return False
    return True
    

def valid_function_name(function):
    p1 = Popen(["cat", "/proc/kallsyms"], stdout=PIPE)
    p2 = Popen(["grep", function], stdin=p1.stdout, stdout=PIPE)
    out = p2.stdout.read()
    lines = out.split('\n')
    entries = len(lines) - 1
    if entries == 0:
        print "%s() is not traceable." % (function)
    elif entries == 1:
        function_name = lines[0].split()[2]
        if __check_name(function, function_name) == NAME_NOT:
            print "%s matches %s()." % (function, function_name)
        else:
            return function_name
    else:
        name_list = list()
        for i in range(0, entries):
            function_name = lines[i].split()[2]
            flag =  __check_name(function, function_name)
            if flag == NAME_EQUAL:
                return function
            elif flag == NAME_PREFIX or flag == NAME_SUFFIX:
                name_list.append(function_name)
        if len(name_list) == 0:
            print "%s() is not traceable." % (function)
        if len(name_list) > 1: 
            print "Multiple functions %s match with \"%s\". Please be specific." % (name_list, function)
        else:
            return name_list[0]

    return
