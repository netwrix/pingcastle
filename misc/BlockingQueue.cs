//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.Collections.Generic;
using System.Threading;

namespace PingCastle.misc
{
    public class BlockingQueue<T>
    {
        readonly int _Size = 0;
        readonly Queue<T> _Queue = new Queue<T>();
        readonly object _Key = new object();
        bool _Quit = false;

        public BlockingQueue(int size)
        {
            _Size = size;
        }

        public void Quit()
        {
            lock (_Key)
            {
                _Quit = true;
                Monitor.PulseAll(_Key);
            }
        }

        public bool Enqueue(T t)
        {
            lock (_Key)
            {
                while (!_Quit && _Queue.Count >= _Size) Monitor.Wait(_Key);
                if (_Quit) return false;
                _Queue.Enqueue(t);
                Monitor.PulseAll(_Key);
            }
            return true;
        }

        public bool Dequeue(out T t)
        {
            t = default(T);
            lock (_Key)
            {
                while (!_Quit && _Queue.Count == 0) Monitor.Wait(_Key);
                if (_Queue.Count == 0) return false;
                t = _Queue.Dequeue();
                Monitor.PulseAll(_Key);
            }
            return true;
        }
    }
}
