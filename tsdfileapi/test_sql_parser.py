
from db import sqlite_init, sqlite_insert, sqlite_get_data, sqlite_update_data, sqlite_delete_data
from parser import SqlStatement

if __name__ == '__main__':
    test_data = [
        {
            'x': 0,
            'y': 1,
            'z': None,
            'b':[1, 2, 5, 1],
            'c': None,
            'd': 'string1'
        },
        {
            'y': 11,
            'z': 1,
            'c': [
                {
                    'h': 3,
                    'p': 99,
                    'w': False
                },
                {
                    'h': 32,
                    'p': False,
                    'w': True,
                    'i': {
                        't': [1,2,3]
                    }
                },
                {
                    'h': 0
                }
            ],
            'd': 'string2'
        },
        {
            'a': {
                'k1': {
                    'r1': [1, 2],
                    'r2': 2
                },
                'k2': ['val', 9]
            },
            'z': 0,
            'x': 88,
            'd': 'string3'
        },
        {
            'a': {
                'k1': {
                    'r1': [33, 200],
                    'r2': 90
                },
                'k2': ['val222', 90],
                'k3': [{'h': 0}]
            },
            'z': 10,
            'x': 107
        },
        {
            'x': 10
        }
    ]
    create_engine = sqlite_init('/tmp', name='file-api-test.db')
    query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
    sqlite_delete_data(query_engine, 'mytable', '/mytable')
    sqlite_insert(create_engine, 'mytable', test_data)
    select_uris = [
        # selections
        '/mytable',
        '/mytable?select=x',
        '/mytable?select=x,y',
        '/mytable?select=x,a.k1',
        '/mytable?select=x,a.k1.r1',
        '/mytable?select=a.k1.r1',
        '/mytable?select=a.k1.r1',
        '/mytable?select=b[1]',
        '/mytable?select=a,b[1]',
        '/mytable?select=a.k1.r1[0]',
        '/mytable?select=c[0].h',
        '/mytable?select=a.k3[0].h',
        '/mytable?select=x,y,c[0].h,b[1]',
        '/mytable?select=c[0].(h,p)',
        '/mytable?select=c[*].h',
        '/mytable?select=c[*].(h,p)',
        '/mytable?select=y,c[*].(h,i)',
        # filtering
        # TODO: consider supporting OR, and grouped conditions
        # possibile approach
        # &where=x=not.is.null
        # &where=(x=not.like.*zap:and:y=not.is.null)
        # &where=(x=not.like.*zap:and:y=not.is.null)
        # &where=((x=not.like.*zap:and:y=not.is.null):or:z=eq.0)
        '/mytable?select=x&z=eq.5&y=gt.0',
        '/mytable?x=not.like.*zap&y=not.is.null',
        #'/mytable?d=in.(string1,string2)', # TODO, for string only
        '/mytable?select=z&a.k1.r2=eq.2',
        '/mytable?select=z&a.k1.r1[0]=eq.1',
        '/mytable?select=z&a.k3[0].h=eq.0',
        # ordering
        '/mytable?order=y.desc',
        '/mytable?order=a.k1.r2.desc',
        '/mytable?order=b[0].asc',
        '/mytable?order=a.k3[0].h.asc',
        '/mytable?order=a.k3[0].h.desc',
        # with range
        '/mytable?select=x&range=0.2',
        '/mytable?range=2.3',
        # combined functionality
        '/mytable?select=x,c[*].(h,p),a.k1,b[0]&x=not.is.null&order=x.desc&range=1.2'
    ]
    update_uris = [
        '/mytable?set=x.5,y.6&z=eq.5',
        # TODO: support
        # '/mytable?set=a.k1.r2.5&z=eq.0',
        # '/mytable?set=b[0].677&b=not.is.null',
        # '/mytable?set=a.k1.r1[0].35',
        # '/mytable?set=c[0].h.4',
    ]
    delete_uris = [
        '/mytable?z=not.is.null'
    ]
    # test regexes for single column selection strategies
    sql = SqlStatement('')
    # slice present
    assert not sql.idx_present.match('x')
    assert sql.idx_present.match('x[11]')
    assert sql.idx_present.match('x[1]')
    assert sql.idx_present.match('x[*]')
    # single slice
    assert not sql.idx_single.match('x[*]')
    assert sql.idx_single.match('x[1]')
    assert sql.idx_single.match('x[12]')
    # subselect present
    assert not sql.subselect_present.match('x[1]')
    assert sql.subselect_present.match('x[*].k')
    assert sql.subselect_present.match('x[1:9].(k,j)')
    # subselect single
    assert sql.subselect_single.match('x[*].k')
    # subselect mutliple
    assert not sql.subselect_multiple.match('x[*].k')
    # column quoting
    print(sql.quote_column_selection('x'))
    print(sql.quote_column_selection('x.y'))
    print(sql.quote_column_selection('y[1]'))
    print(sql.quote_column_selection('y[1].z'))
    print(sql.quote_column_selection('y[1].(z,a)'))
    print(sql.quote_column('erd.ys[1].(z,a)'))
    print(sql.quote_column('erd.ys[1].z'))
    print(sql.quote_column('"erd"."ys"[1]."z"'))
    print(sql.smart_split('x,y[1].(f,m,l),z'))
    print(sql.smart_split('x,y[1].k'))
    #print(sql.quote_column(',x,y[1].(z,a)')) - should error
    for uri in select_uris:
        try:
            print(uri)
            query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
            print(sqlite_get_data(query_engine, 'mytable', uri, verbose=True))
            print()
        except Exception:
            pass
    for uri in update_uris:
        try:
            print(uri)
            query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
            print(sqlite_update_data(query_engine, 'mytable', uri, verbose=True))
            query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
            print(sqlite_get_data(query_engine, 'mytable', '/mytable'))
            print()
        except Exception:
            pass
    for uri in delete_uris:
        print(uri)
        query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
        print(sqlite_delete_data(query_engine, 'mytable', uri, verbose=True))
        query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
        print(sqlite_get_data(query_engine, 'mytable', '/mytable'))
