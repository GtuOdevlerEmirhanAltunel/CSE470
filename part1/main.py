"""Prime Number Tester"""

import sys
import random
import time
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QVBoxLayout,
    QComboBox,
    QLineEdit,
    QPushButton,
    QLabel,
    QWidget,
)
from PyQt6.QtCore import Qt


# GUI Application
class PrimeNumberTester(QMainWindow):
    """Prime Number Tester"""

    def __miller_rabin(self, n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def __sieve_of_eratosthenes(self, limit):
        primes = [True] * (limit + 1)
        primes[0], primes[1] = False, False
        for i in range(2, int(limit**0.5) + 1):
            if primes[i]:
                for j in range(i * i, limit + 1, i):
                    primes[j] = False
        return [x for x, is_prime in enumerate(primes) if is_prime]

    def __sieve_of_atkin(self, limit):
        sieve = [False] * (limit + 1)
        sieve[2] = sieve[3] = True
        for x in range(1, int(limit**0.5) + 1):
            for y in range(1, int(limit**0.5) + 1):
                n = 4 * x**2 + y**2
                if n <= limit and (n % 12 == 1 or n % 12 == 5):
                    sieve[n] = not sieve[n]
                n = 3 * x**2 + y**2
                if n <= limit and n % 12 == 7:
                    sieve[n] = not sieve[n]
                n = 3 * x**2 - y**2
                if x > y and n <= limit and n % 12 == 11:
                    sieve[n] = not sieve[n]
        for n in range(5, int(limit**0.5) + 1):
            if sieve[n]:
                for k in range(n * n, limit + 1, n * n):
                    sieve[k] = False
        return [x for x, is_prime in enumerate(sieve) if is_prime]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Prime Number Tester")
        self.setGeometry(300, 200, 400, 300)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Input field
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter a number/limit...")
        layout.addWidget(self.input_field)

        # Algorithm selection
        self.algorithm_selector = QComboBox()
        self.algorithm_selector.addItems(
            ["Miller-Rabin", "Eratosthenes", "Atkin"]
        )
        layout.addWidget(self.algorithm_selector)

        # Run button
        self.run_button = QPushButton("Run Algorithm")
        self.run_button.clicked.connect(self.run_algorithm)
        layout.addWidget(self.run_button)

        # Time label
        self.time_label = QLabel("Time elapsed: 0.0 seconds")
        layout.addWidget(self.time_label)
        self.time_label.setVisible(False)

        # Output label
        self.output_label = QLabel("Results will appear here.")
        self.output_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.output_label.setWordWrap(True)
        layout.addWidget(self.output_label)

        # Set layout
        central_widget.setLayout(layout)

    def run_algorithm(self):
        """Run the selected algorithm"""
        number = self.input_field.text()
        if not number.isdigit():
            self.output_label.setText("Please enter a valid number.")
            return

        number = int(number)
        algorithm = self.algorithm_selector.currentText()
        start_time = time.time()
        if algorithm == "Miller-Rabin":
            result = self.__miller_rabin(number)
            self.output_label.setText(
                f"Number {number} is {'Prime' if result else 'Not Prime'}"
                " (Miller-Rabin)."
            )
        elif algorithm == "Eratosthenes":
            primes = self.__sieve_of_eratosthenes(number)
            self.output_label.setText(
                f"Primes up to {number} (Eratosthenes):\n"
                f"{", ".join(map(str, primes))}"
            )
        elif algorithm == "Atkin":
            primes = self.__sieve_of_atkin(number)
            self.output_label.setText(
                f"Primes up to {number} (Atkin):\n"
                f"{", ".join(map(str, primes))}"
            )
        end_time = time.time()
        elapsed_time = end_time - start_time
        elapsed_time *= 1000
        self.time_label.setText(f"Time elapsed: {elapsed_time:.4f} ms")
        self.time_label.setVisible(True)


# Main entry
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PrimeNumberTester()
    window.show()
    sys.exit(app.exec())
