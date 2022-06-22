# Google CTF Beginners Quest

### Task 1 : CHEMICAL PLANT CCTV (REV)
LINK : https://cctv-web.2021.ctfcompetition.com/
```js
/*
Task - 1
CHEMICAL PLANT
Category : Reverse Engineering
*/

// Main task is to identify what charCodeAt function does in the javascript

/*
p[0] === 52037 &&
     p[6] === 52081 &&
     p[5] === 52063 &&
     p[1] === 52077 &&
     p[9] === 52077 &&
     p[10] === 52080 &&
     p[4] === 52046 &&
     p[3] === 52066 &&
     p[8] === 52085 &&
     p[7] === 52081 &&
     p[2] === 52077 &&
     p[11] === 52066
*/    

const chars_req = [52037,52077,52077,52066,52046,52063,52081,52081,52085,52077,52080,52066]

ans = ""

for(let i = 0; i < chars_req.length; i++){
    ans += String.fromCharCode(chars_req[i]-0xCafe);
}

console.log(ans);
```

**ANS : GoodPassword**

### Task 2 : APARTMENT LOGIC LOCK (MISC)

<img src="./logic-lock.png" width="100%"></img>

**ANS : CTF{BCFIJ}**


### Task 3 : HIGH SPEED CHASE (MISC)

```js
function controlCar(scanArray) {
     // We need to calculate the maximum distance of the nearest obstacle 
     let max_distance = scanArray[0]
     let max_distance_index = 0
     for (let i = 0; i < 17; i++){
        if(max_distance < scanArray[i]){
            max_distance = scanArray[i];
            max_distance_index = i;
        }
     }
     
     // if max distance is equal for 7,8,9 indexes then move straight
     if (max_distance == scanArray[7] && max_distance == scanArray[8] && max_distance == scanArray[9]){
        return 0;
     }

     if (max_distance_index < 8){
        return -1;
     }

     if(max_distance_index > 8){
        return 1;
     }
     
     return 1;
}
```

**ANS : CTF{cbe138a2cd7bd97ab726ebd67e3b7126707f3e7f}**


### Task 5 : TWISTED ROBOT (MISC)

**///code avialable above in folder named "twisted robot"///**

The vulnerable function is **getrandbits** which is there in the encodeSecret function
Now we can decrypt our secret using this method :

https://github.com/eboda/mersenne-twister-recover

Now we need to write our script to decode our secret. As we read from th readme we need 624 set of integers in order to decrypt our secret and if we notice we will see that there are 624 phone numbers now we will make array out of the 624 phone numbers and format them as below ->

**arrayNum.py**

```python
array_num = [2631706234 - (1<<31),
4675537030 - (1<<31),
2201461293 - (1<<31),
6303286023 - (1<<31),
4135530465 - (1<<31),
5284036609 - (1<<31),
4546416157 - (1<<31),
3969061900 - (1<<31),
...
...
...]
```

Now we need to Clone the repo above into our folder in order to use the function.

```bash
git clone https://github.com/eboda/mersenne-twister-recover
```

Now we will write our script ->

**exploit.py**

Take the code given in the readme of the repo and modify it

```python
from MTRecover import MT19937Recover
from arrayNum import array_num
# Not needed
# r1 = random.Random(31337)
# outputs = [r1.getrandbits(32) for _ in range(625)]

mtr = MT19937Recover()
r2 = mtr.go(array_num)

# Write our encode function here
# We removed the encode function because we don't need to do that


def encodeSecret(s):
    key = [r2.getrandbits(8) for i in range(len(s))]
    return bytes([a ^ b for a, b in zip(key, s)])


# Now opening/creating our secret.enc file
with open("secret.enc", "rb") as f:
    data = f.read()

print(encodeSecret(data))

# assert r1.getrandbits(32) == r2.getrandbits(32)
```

**ANS : CTF{n3v3r_3ver_ev3r_use_r4nd0m}**


