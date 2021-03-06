from sklearn import datasets
from sklearn import svm


iris = datasets.load_iris()
digits = datasets.load_digits()

print(digits.data)
digits.target

clf = svm.SVC(gamma=0.001, C=100.)

clf.fit(digits.data[:-1], digits.target[:-1])  

output = clf.predict(digits.data[-1:])
print output
