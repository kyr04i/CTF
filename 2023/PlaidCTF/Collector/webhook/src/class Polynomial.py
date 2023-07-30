class Polynomial:
    def __init__(self, n=0, coeffs=None):
        if coeffs is None:
            coeffs = []
        self.n = n
        self.coeffs = coeffs

    def input(self):
        self.n = int(input())
        self.coeffs = []
        for i in range(self.n+1):
            self.coeffs.append(int(input()))

    def output(self):
        for i in range(self.n, -1, -1):
            if self.coeffs[i] != 0:
                if i == self.n:
                    print(self.coeffs[i], end='')
                elif i == 1:
                    print(' + ' if self.coeffs[i] > 0 else ' - ', end='')
                    print(abs(self.coeffs[i]), 'x', end='')
                else:
                    print(' + ' if self.coeffs[i] > 0 else ' - ', end='')
                    print(abs(self.coeffs[i]), 'x^', i, end='')
        if self.coeffs == [0]*(self.n+1):
            print('0', end='')
        print()

    def __add__(self, other):
        m = max(self.n, other.n)
        coeffs = [0]*(m+1)
        for i in range(m+1):
            coeffs[i] = self.coeffs[i] + other.coeffs[i]
        return Polynomial(m, coeffs)

    def __sub__(self, other):
        m = max(self.n, other.n)
        coeffs = [0]*(m+1)
        for i in range(m+1):
            coeffs[i] = self.coeffs[i] - other.coeffs[i]
        return Polynomial(m, coeffs)

    def __mul__(self, other):
        m = self.n + other.n
        coeffs = [0]*(m+1)
        for i in range(self.n+1):
            for j in range(other.n+1):
                coeffs[i+j] += self.coeffs[i] * other.coeffs[j]
        return Polynomial(m, coeffs)


if __name__ == '__main__':
    p1 = Polynomial()
    p1.input()

    p2 = Polynomial()
    p2.input()

    operator = input()

    if operator == '+':
        result = p1 + p2
    elif operator == '-':
        result = p1 - p2
    elif operator == '*':
        result = p1 * p2

    result.output()
