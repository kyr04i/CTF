from fractions import Fraction

from fractions import Fraction

def calc(e):
    stack = [Fraction(0)]
    i = 0
    while i < len(e):
        if e[i] == '(':
            j = i + 1
            cnt = 1
            while cnt != 0:
                if e[j] == '(':
                    cnt += 1
                elif e[j] == ')':
                    cnt -= 1
                j += 1
            value = calc(e[i+1:j-1])
            stack.append(value)
            i = j
        elif e[i] == '*':
            value1 = stack.pop()
            value2 = calc(e[i+1:])
            stack.append(value1 * value2)
            break
        elif e[i] == '/':
            value1 = stack.pop()
            value2 = calc(e[i+1:])
            stack.append(value1 / Fraction(value2))
            break
        elif e[i] == '**':
            value1 = stack.pop()
            value2 = calc(e[i+2:])
            stack.append(value1 ** value2)
            break
        elif e[i] == '+':
            value1 = stack.pop()
            value2 = calc(e[i+1:])
            stack.append(value1 + value2)
            break
        elif e[i] == '-':
            value1 = stack.pop()
            value2 = calc(e[i+1:])
            stack.append(value1 - value2)
            break
        else:
            j = i
            while j < len(e) and e[j] != '(' and e[j] not in ['+', '-', '*', '/', '**']:
                j += 1
            value = Fraction(e[i:j])
            stack.append(value)
            i = j
    result = stack[0]
    for i in range(1, len(stack)):
        result += stack[i]
    return result

def main():
    e = input("Enter an expression: ")
    result = calc(e.strip())
    print(f"Result: {result}")

if __name__ == '__main__':
    main()
