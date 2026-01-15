# dSyncAuth

`dSyncAuth ` is an addition to `dSync` that uses `dSyncSign` to create random encrypted challenges and checks if the decrypted response from a user is correct. It also requires `epxress`.

> [!IMPORTANT]
>
> This document is work in progress and will be updated in the future. It will show more examples and details somewhere in the future.

------

## Init

The following example is a very basic example on how to initialize dSyncAuth. Once you've done this its already good to go.

```js
import dSyncAuth from '@hackthedev/dsync-auth';
import { dSyncSign } from "@hackthedev/dsync-sign";

const signer = new dSyncSign();
const auther = new dSyncAuth(app, signer)
```

You can also define callbacks to capture specific events, like `onVerify` and `onLogin` like this.

```js
const auther = new dSyncAuth(app, signer, async function(data) {
    if(data.valid === true){
        // do something with the data
    }
});
```

