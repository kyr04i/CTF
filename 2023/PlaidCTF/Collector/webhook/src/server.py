from fractions import Fraction

def calculate(expression):
    stack = []
    i = 0
    while i < len(expression):
        if expression[i] == '(':
            j = i + 1
            count = 1
            while count != 0:
                if expression[j] == '(':
                    count += 1
                elif expression[j] == ')':
                    count -= 1
                j += 1
            value = calculate(expression[i+1:j-1])
            stack.append(value)
            i = j
        elif expression[i] == '*':
            value1 = stack.pop()
            value2 = calculate(expression[i+1:])
            stack.append(value1 * value2)
            break
        elif expression[i] == '/':
            value1 = stack.pop()
            value2 = calculate(expression[i+1:])
            stack.append(value1 / value2)
            break
        elif expression[i] == '**':
            value1 = stack.pop()
            value2 = calculate(expression[i+2:])
            stack.append(value1 ** value2)
            break
        elif expression[i] == '+':
            value1 = stack.pop()
            value2 = calculate(expression[i+1:])
            stack.append(value1 + value2)
            break
        elif expression[i] == '-':
            value1 = stack.pop()
            value2 = calculate(expression[i+1:])
            stack.append(value1 - value2)
            break
        else:
            j = i
            while j < len(expression) and expression[j] != '(' and expression[j] not in ['+', '-', '*', '/', '**']:
                j += 1
            value = Fraction(expression[i:j])
            stack.append(value)
            i = j
    result = stack[0]
    for i in range(1, len(stack)):
        result += stack[i]
    return result

expression = input().strip()
result = calculate(expression)

# if result.denominator == 1:
#     result = Fraction(result.numerator, 1)

result_str = str(result)

print(result_str)

if result.denominator != 1:
    print(round(float(result), 2))









