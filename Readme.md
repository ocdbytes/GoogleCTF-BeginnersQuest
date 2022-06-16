# Google CTF Beginners Quest

### Task 1 : CHEMICAL PLANT CCTV REV

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
